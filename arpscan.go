package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	ArpJsonName     = "arpscan"                   //Arp日志文件
	ArpLogName      = "arpscanlog"                //初始Arp日志文件
	IpStatus1       = "FirstObtain-IP Obtain"     //IP首次获得
	IpStatus2       = "Already Exist-IP Maintain" // IP维持不变
	IpStatus3       = "New Appear-IP change"      //IP分配变化
	ArpInfs         []ArpInf                      //Arp记录
	logFileTime     = time.Now()                  //记录程序运行时的初始时间
	logFileDuration = 1                           //日志切割的间隔时间
	WriteStatus     = 0                           //默认为0均写入，1只写入IP地址变更，2只写入新的IP出现
)

type ArpInf struct {
	HwAddress string  //网卡硬件mac地址
	NowIp     string  //当前IPv4地址
	Ipv4Inf   []IpInf //历史IPv4地址
}

type IpInf struct {
	Ipv4Address string `json:"Ipv4Address"`
	IpTime      string `json:"IpTime"`
}

type ArpResponse struct {
	HwAddress   string
	Ipv4Address string
	Index       int
	Name        string
}

type ArpEvent struct {
	HwAddress   string `json:"HwAddress"`
	IPv4Address string `json:"Ipv4Address"`
	IpTime      string `json:"IpTime"`
	Status      string `json:"Status"`
}

func main() {

	//启动处理
	InitArpScan()
	LoadArpJsonLog(ArpLogName)

	// Get a list of all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	for _, iface := range ifaces {
		wg.Add(1)
		// Start up a scan on each interface.
		go func(iface net.Interface) {
			defer wg.Done()
			if err := scan(&iface); err != nil {
				log.Printf("interface %v: %v", iface.Name, err)
			}
		}(iface)
	}
	// Wait for all interfaces' scans to complete.  They'll try to run
	// forever, but will stop on an error, so if we get past this Wait
	// it means all attempts to write have failed.
	wg.Wait()
}

// scan scans an individual interface's local network for machines using ARP requests/replies.
//
// scan loops forever, sending packets out regularly.  It returns an error if
// it's ever unable to write a packet.
func scan(iface *net.Interface) error {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}
	// Sanity-check that the interface has a good address.
	if addr == nil {
		return errors.New("no good IP network found")
	} else if addr.IP[0] == 127 {
		return errors.New("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return errors.New("mask means network is too large")
	}
	log.Printf("Using network range %v for interface %v", addr, iface.Name)

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go readARP(handle, iface, stop)
	defer close(stop)
	for {
		// Write our scan packets out to the handle.
		if err := writeARP(handle, iface, addr); err != nil {
			log.Printf("error writing packets on %v: %v", iface.Name, err)
			return err
		}
		// We don't know exactly how long it'll take for packets to be
		// sent back to us, but 10 seconds should be more than enough
		// time ;)
		time.Sleep(10 * time.Second)
	}
}

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
//
// readARP loops until 'stop' is closed.
func readARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
				// This is a packet I sent.
				continue
			}
			// Note:  we might get some packets here that aren't responses to ones we've sent,
			// if for example someone else sends US an ARP request.  Doesn't much matter, though...
			// all information is good information :)
			log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))

			//形成Arp日志记录
			var newinf = ArpResponse{
				HwAddress:   net.HardwareAddr(arp.SourceHwAddress).String(),
				Ipv4Address: net.IP(arp.SourceProtAddress).String(),
				Index:       iface.Index,
				Name:        iface.Name,
			}
			FormArpJson(newinf)
		}
	}
}

// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.
	for _, ip := range ips(addr) {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// ips is a simple and not very good method for getting all IPv4 addresses from a
// net.IPNet.  It returns all IPs it can over the channel it sends back, closing
// the channel when done.
func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	network := num & mask
	broadcast := network | ^mask
	for network++; network < broadcast; network++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], network)
		out = append(out, net.IP(buf[:]))
	}
	return
}

func FormArpJson(newinf ArpResponse) {

	var ArpJsonFile = ArpJsonName + ".json"
	var JudgeIp [3]int = [3]int{0, 0, 0}
	// 打开文件
	file, err := os.OpenFile(ArpJsonFile, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return
	}

	var NewArpEvent = ArpEvent{
		HwAddress:   newinf.HwAddress,
		IPv4Address: newinf.Ipv4Address,
		Status:      "",
		IpTime:      time.Now().String(),
	}

	// 解码JSON
	var arpevents []ArpEvent
	// 解码JSON内容
	decoder := json.NewDecoder(file)
	for decoder.More() {
		var arpevent ArpEvent
		if err := decoder.Decode(&arpevent); err != nil {
			fmt.Println("Error decoding JSON:", err)
			return
		}
		arpevents = append(arpevents, arpevent)
	}
	var exist = false
	for i, oldinf := range ArpInfs {
		if oldinf.HwAddress == newinf.HwAddress {
			if oldinf.NowIp != newinf.Ipv4Address {
				oldinf.NowIp = newinf.Ipv4Address
				var newipinf = IpInf{
					Ipv4Address: newinf.Ipv4Address,
					IpTime:      time.Now().String(),
				}
				ArpInfs[i].Ipv4Inf = append(ArpInfs[i].Ipv4Inf, newipinf)
				NewArpEvent.Status = IpStatus3
				JudgeIp[1] = 1
				for _, existip := range oldinf.Ipv4Inf {
					if existip.Ipv4Address == newinf.Ipv4Address {
						JudgeIp[2] = 2
					}
				}
				if JudgeIp[2] != 2 {
					JudgeIp[2] = 1
				} else {
					JudgeIp[2] = 0
				}

			} else {
				NewArpEvent.Status = IpStatus2
			}
			exist = true
		}
	}
	if !exist {
		var newipinf = IpInf{
			Ipv4Address: newinf.Ipv4Address,
			IpTime:      time.Now().String(),
		}
		var newipinfs []IpInf
		newipinfs = append(newipinfs, newipinf)
		var newarpinf = ArpInf{
			HwAddress: newinf.HwAddress,
			NowIp:     newinf.Ipv4Address,
			Ipv4Inf:   newipinfs,
		}
		ArpInfs = append(ArpInfs, newarpinf)
		NewArpEvent.Status = IpStatus1
		JudgeIp[2] = 1
	}

	// 根据参数判断是否添加新的JSON对象
	var Write = false
	if WriteStatus == 2 && JudgeIp[2] == 1 {
		Write = true
	}
	if WriteStatus == 1 && JudgeIp[1] == 1 {
		Write = true
	}
	if WriteStatus == 0 {
		Write = true
	}
	if Write {
		arpevents = append(arpevents, NewArpEvent)
	}

	// 将更新后的内容重新写入文件
	file.Truncate(0) // 清空文件内容
	file.Seek(0, 0)

	//超出时间间隔则写在新日志文件中
	var nowtime = time.Now().Hour()
	if nowtime-logFileTime.Hour() < 0 {
		nowtime = nowtime + 24
	}
	if nowtime-logFileTime.Hour() >= logFileDuration {
		var ArpJsonLog = ArpJsonName + "-" + logFileTime.Format("2006-01-02 15") + ".json"
		file, _ = os.OpenFile(ArpJsonLog, os.O_RDWR|os.O_CREATE, 0755)
		logFileTime = time.Now()
	}
	encoder := json.NewEncoder(file)
	for _, arpevent := range arpevents {
		if err := encoder.Encode(arpevent); err != nil {
			fmt.Println("Error encoding JSON:", err)
			return
		}
	}
	defer file.Close()
}

func InitArpScan() {

	//读人命令行参数
	args := os.Args[1:]

	// 输出传递的参数
	if len(args) > 1 {
		if strings.Contains(strings.ToLower(args[1]), "new") {
			WriteStatus = 2
		} else {
			if strings.Contains(strings.ToLower(args[1]), "modify") {
				WriteStatus = 1
			}
		}
	}
}

func LoadArpJsonLog(NameOfArpLogFile string) {
	file, _ := os.OpenFile(NameOfArpLogFile+".json", os.O_RDWR|os.O_CREATE, 0755)
	// 解码JSON
	var arpevents []ArpEvent
	// 解码JSON内容
	decoder := json.NewDecoder(file)
	for decoder.More() {
		var arpevent ArpEvent
		if err := decoder.Decode(&arpevent); err != nil {
			fmt.Println("Error decoding JSON:", err)
			return
		}
		arpevents = append(arpevents, arpevent)
	}
	//初始化Arp日志记录
	for i, _ := range arpevents {
		var exist = false
		for j, _ := range ArpInfs {
			if arpevents[i].HwAddress == ArpInfs[j].HwAddress {
				exist = true
				if ContainsIpv4(ArpInfs[j].Ipv4Inf, arpevents[i].IPv4Address) {
					if ArpInfs[j].NowIp != arpevents[i].IPv4Address {
						var newipinf = IpInf{
							Ipv4Address: arpevents[i].IPv4Address,
							IpTime:      arpevents[i].IpTime,
						}
						ArpInfs[j].Ipv4Inf = append(ArpInfs[j].Ipv4Inf, newipinf)
						ArpInfs[i].NowIp = newipinf.Ipv4Address
					}
				} else {
					var newipinf = IpInf{
						Ipv4Address: arpevents[i].IPv4Address,
						IpTime:      arpevents[i].IpTime,
					}
					ArpInfs[j].Ipv4Inf = append(ArpInfs[j].Ipv4Inf, newipinf)
					ArpInfs[j].NowIp = newipinf.Ipv4Address
				}
			}
		}
		if !exist {
			var newarpips []IpInf
			var newarpinf = ArpInf{
				HwAddress: arpevents[i].HwAddress,
				NowIp:     arpevents[i].IPv4Address,
				Ipv4Inf:   newarpips,
			}
			ArpInfs = append(ArpInfs, newarpinf)
		}
	}
}

func ContainsIpv4(ipArray []IpInf, ipv4address string) bool {
	for i, _ := range ipArray {
		if ipArray[i].Ipv4Address == ipv4address {
			return true
		}
	}
	return false
}
