package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"
)

type Watch struct {
	HWAddress net.HardwareAddr
	Threshold time.Duration
	URL string
	LastSeen time.Time
	RunCount uint16
}

func (w *Watch) check() {
	if time.Since(w.LastSeen) > w.Threshold {
		w.execute()
	}
	w.LastSeen = time.Now()
}

func (w *Watch) execute() {
	if w.RunCount > 0 {
		_, err := http.Get(w.URL)
		if err != nil {
			panic("Could not make request to URL")
		}
	}
	w.RunCount++
}

var watches []Watch

func main() {
	args := os.Args[1:]
	if !checkForRoot() {
		fmt.Println("You need to run this utility as root")
		return
	}
	if len(args) == 1 {
		if args[0] == "-list" {
			listInterfaces()
			return
		}
	}
	if len(args) != 2 {
		printHelp()
		return
	}
	if args[0] == "-list" {
		listInterfaces()
	}else {
		parseConfigJSON(args[1])
		go webServe()
		scanInterface(args[0])
	}
}

func checkForRoot() bool{
	cmd := exec.Command("id", "-u")
	output, err := cmd.Output()
	if err != nil {
		panic("Could not determine root user")
	}
	uid, err := strconv.Atoi(string(output[:len(output) - 1]))
	return uid == 0
}

func printHelp(){
	fmt.Println("network-watch-tower")
	fmt.Println("")
	fmt.Println("Given a device's hardware address, interval and URL - will make")
	fmt.Println("a GET request to a URL when the device has been missing from")
	fmt.Println("the local network for a given period of time.")
	fmt.Println("")
	fmt.Println("Perfect for switching your lights on via IFTTT when you leave")
	fmt.Println("home.")
	fmt.Println("")
	fmt.Println("USAGE: watch [-list] <interface> <config file>")
	fmt.Println("         -list         Lists available interfaces to watch")
	fmt.Println("")
	fmt.Println("         <interface>   The interface to be scanned")
	fmt.Println("         <config file> JSON config file")
	fmt.Println("")
	fmt.Println("Example JSON config file:")
	fmt.Println("[")
	fmt.Println("  {")
	fmt.Println("    \"HWAddress\": \"00:00:00:00:00:00\",")
	fmt.Println("    \"Duration\": \"1h\",")
	fmt.Println("    \"URL\": \"https://some.url.to.call\"")
	fmt.Println("  }")
	fmt.Println("]")
	fmt.Println("")
}

func parseConfigJSON(fileName string) {
	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic("Could not load configuration file")
	}
	var mapped []map[string]string
	json.Unmarshal([]byte(content), &mapped)
	for _,i := range mapped {
		hwAddr, err := net.ParseMAC(i["HWAddress"])
		if err != nil {
			panic("Invalid HW address")
		}
		duration, err := time.ParseDuration(i["Duration"])
		if err != nil {
			panic("Invalid duration")
		}
		watch := Watch{
			HWAddress: hwAddr,
			Threshold: duration,
			URL: i["URL"],
		}
		watches = append(watches, watch)
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
	for {
		sendARP(handle, iface, addr)
		time.Sleep(10 * time.Second)
	}
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
			checkArpResponse(arp)
		}
	}
}

func checkArpResponse(arp *layers.ARP) {
	sampleHw := net.HardwareAddr(arp.SourceHwAddress)
	for index, watch := range watches {
		if string(watch.HWAddress) == string(sampleHw) {
			watches[index].check()
		}
	}
}

func webServe() {
	http.HandleFunc("/", webHandler)
	http.ListenAndServe(":8080", nil)
}

func webHandler(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintln(w, "<!DOCTYPE html>")
	fmt.Fprintln(w, "<html>")
	fmt.Fprintln(w, "<head>")
	fmt.Fprintln(w, "<title>Network Watch Tower</title>")
	fmt.Fprintln(w, "</head>")
	fmt.Fprintln(w, "<body>")
	for _, watch := range watches {
		fmt.Fprintf(w, "<h3>%s</h3><br>Last seen: %s<br>Executed: %d times<br><hr>", watch.HWAddress, watch.LastSeen, watch.RunCount)
	}
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
}