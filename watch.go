package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"os"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Print("No interface has been specified")
		return
	}
	if args[0] == "-list" {
		listInterfaces()
	}else {
		scanInterface(args[0])
	}
}

func listInterfaces(){
	interfaces, err := net.Interfaces()
	if err != nil {
		panic("Could not list interfaces")
	}
	fmt.Println("Listing all available interfaces:")
	for _,i := range interfaces {
		fmt.Println(i.Name)
	}
}

func scanInterface(name string) {
	var addr *net.IPNet
	fmt.Println("Scanning interface ", name)
	iface, err := net.InterfaceByName(name)
	if err != nil {
		panic("Could not find interface: " + name)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		panic("Could not retrieve addresses for: " + name)
	}
	for _,x := range addrs {
		if ipnet, ok := x.(*net.IPNet); ok {
			if ipv4 := ipnet.IP.To4(); ipv4 != nil {
				addr = &net.IPNet{
					IP: ipv4,
					Mask: ipnet.Mask[len(ipnet.Mask)-4:],
				}
				break
			}
		}
	}
	if addr == nil {
		panic("No network address found for interface: " + name)
	} else if addr.IP[0] == 127 {
		panic("Cannot use a loopback address")
	}
	fmt.Println("IPv4 addresses for interface: ", addr)

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		panic("Cannot create handle for packet read / writes")
	}
	defer handle.Close()
	stop := make(chan struct{})
	go receiveARP(handle, iface, stop)
	defer close(stop)
}

func sendARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) {
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
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	allIpAddresses := allIpAddresses(addr)
	fmt.Println("Sending packets to ", len(allIpAddresses), " addresses")
	for _, ip := range allIpAddresses {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			panic("Could not send packet")
		}
	}
}

func allIpAddresses(addr *net.IPNet) (output []net.IP) {
	num := binary.BigEndian.Uint32([]byte(addr.IP))
	mask := binary.BigEndian.Uint32([]byte(addr.Mask))
	num &= mask
	for mask < 0xffffffff {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], num)
		output = append(output, net.IP(buf[:]))
		mask++
		num++
	}
	return
}

func receiveARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}) {
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
				continue
			}
			fmt.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
		}
	}
}