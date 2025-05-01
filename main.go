package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	interfaceprint "ldgo/interfacePrint"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type SwitchData struct {
	Protocol    string
	SwitchName  string
	Interface   string
	VLAN        string
	SwitchModel string
	VTPDomain   string
}

func (sd SwitchData) String() string {
	b := &strings.Builder{}
	fmt.Fprintln(b, "protocol    : ", sd.Protocol)
	fmt.Fprintln(b, "switch name : ", sd.SwitchName)
	fmt.Fprintln(b, "interface   : ", sd.Interface)
	fmt.Fprintln(b, "VLAN        : ", sd.VLAN)
	fmt.Fprintln(b, "model       : ", sd.SwitchModel)
	fmt.Fprintln(b, "VTP Domain  : ", sd.VTPDomain)
	return b.String()
}

var help = flag.Bool("h", false, "Display the help text and usage of each flag")
var listAdaptors = flag.Bool("l", false, "List the current network interfaces and exit the program. No packets will be captured")
var nicIndex = flag.Int("i", 9999, "Select the index of the network adapter you want to listen on, as displayed by the list flag. -i 0 will listen on the first adapter in the list")
var nicName = flag.String("n", "", "Select the network adapter to listen on by name. Case sensitive. This can be any substring found in the name or description and the first result is chosen. For example, '-n Intel' will return the first adapter where the name or description contains 'Intel'. Default behaviour is an empty string")
var protocol = flag.String("p", "", "Choose to listen on only one protocol. Valid choices are '-p cdp' '-p lldp' '-p icmp'. Default action is to listen for CDP and LLDP. Sepcifying LLDP will set the timeout to 31s unless a none default timeout is chosen. The purpose of ICMP is to enable testing on the given interface. Run a ping from a separate terminal while GoLD is listening for ICMP and you should see a request and a reply per ping")
var outFile = flag.String("o", "", "Choose the directory in which to write the output file, default is the current working directory as returned by os.Getwd() https://pkg.go.dev/os#Getwd")
var timeout = flag.Int("t", 61, "Set how long to listen for in seconds. CDP announces every 60s, LLDP every 30s. Specifying LLDP will set the timeout to 31s if the value is default")
var version = flag.Bool("v", false, "Display version")

const lldpOnlyFilter = "ether[12:2]==0x88cc"
const cdpOnlyFilter = "ether[20:2]==0x2000"
const defaultFilter = "ether[12:2]==0x88cc or ether[20:2]==0x2000"
const icmpFIlter = "icmp[icmptype] == icmp-echo or icmp[icmptype] == icmp-echoreply"
const blurb = "cross platform link discovery"
const kofi = "https://ko-fi.com/dktools"
const versionString = "version: 0.5a"
const repoString = "https://github.com/BadPixel89/ldGO"

func main() {
	flag.Parse()

	log.SetFlags(0)

	if len(os.Args) == 1 {
		//colourtext.PrintInfo("No flags passed, use -h to see helptext")
		color.Cyan("[info] No flags passed, use -h to see helptext")
		*listAdaptors = true
	}
	if *help {
		fmt.Fprintf(os.Stdout, "To run this software you will need:\n\nWindows:\nnPcap https://npcap.com/#download.\n\nLinux:\nlibpcap0.8 to run, libpcap-dev to build\n\nThis is available in most package managers.\n\nIn most environments you will need to run as admin or sudo\n\n")
		flag.CommandLine.Usage()
		os.Exit(0)
		return
	}
	if *version {
		PrintVersionBanner()
		os.Exit(0)
		return
	}

	devicePresent, devName := FindNetworkDevice()

	if *listAdaptors {
		os.Exit(0)
		return
	}

	if !devicePresent {
		if *nicIndex != 9999 || devName != "" {
			fmt.Fprintf(os.Stderr, "[exit] %v\n", "invalid network adapter chosen "+*nicName)
			os.Exit(1)
			return
		}
		fmt.Fprintf(os.Stderr, "[exit] %v\n", "no arguments passed, use the -h flag to see CLI usage")
		os.Exit(1)
	}

	//colourtext.PrintSuccess("device found: " + devName)
	color.Green("[pass] device found: " + devName)

	handle, err := pcap.OpenLive(devName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer handle.Close()

	var filter string = defaultFilter
	switch *protocol {
	case "CDP":
		filter = cdpOnlyFilter
	case "cdp":
		filter = cdpOnlyFilter
	case "LLDP":
		filter = lldpOnlyFilter
	case "lldp":
		filter = lldpOnlyFilter
	case "icmp":
		filter = icmpFIlter
	case "ICMP":
		filter = icmpFIlter
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err.Error())
	}
	//lldp announces every 30s
	if filter == lldpOnlyFilter {
		*timeout = 31
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	killtime := time.After(time.Duration(*timeout) * time.Second)
	//timer to exit afer timeout duration
	go func() {
		<-killtime
		if *protocol == "icmp" || *protocol == "ICMP" {
			color.Cyan("[time] complete")
			os.Exit(0)
		}
		color.Cyan("[time] no packets captured")
		os.Exit(0)
	}()

	color.Green("starting listener with filter '" + filter + "'")
	//	this method returns and quits as soon as it finds any packet matching the filter
	//	except when this is ICMP - in which case it will keep running for the duration of the specified timeout
	switchInfo := StartListening(*packetSource)

	color.Cyan(switchInfo.String())
	err = WriteSwitchDataStructAsJson(switchInfo)
	if err != nil {
		log.Fatal(err.Error())
	}
	handle.Close()
	os.Exit(0)
}
func StartListening(source gopacket.PacketSource) SwitchData {
	for packet := range source.Packets() {
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
		cdpLayer := packet.Layer(layers.LayerTypeCiscoDiscoveryInfo)
		lldpLayer := packet.Layer(layers.LayerTypeLinkLayerDiscovery)
		lldpLayerInfo := packet.Layer(layers.LayerTypeLinkLayerDiscoveryInfo)

		if cdpLayer != nil {
			return ParseCDPToStruct(cdpLayer)
		}
		if lldpLayer != nil && lldpLayerInfo != nil {
			var lldpInfo SwitchData = ParseLLDPToStruct(lldpLayer, lldpLayerInfo)
			//	this will happen when you plug in the network interface while listening, the packets capture will be incomplete
			if lldpInfo.VLAN != "[fail]" {
				return lldpInfo
			}
		}
		if icmpLayer != nil {
			ParseICMPPacket(icmpLayer)
		}
	}
	return SwitchData{}
}
func ParseICMPPacket(icmplayer gopacket.Layer) {
	echo, _ := icmplayer.(*layers.ICMPv4)

	if echo.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
		color.Cyan("ping request")
	}
	if echo.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
		color.Cyan("ping reply")
	}
}
func ParseCDPToStruct(cdpLayer gopacket.Layer) SwitchData {
	cdp, _ := cdpLayer.(*layers.CiscoDiscoveryInfo)

	data := SwitchData{
		Protocol:    "CDP",
		SwitchName:  cdp.DeviceID,
		Interface:   cdp.PortID,
		VLAN:        fmt.Sprint(cdp.NativeVLAN),
		SwitchModel: string(cdp.Platform),
		VTPDomain:   string(cdp.VTPDomain),
	}
	return data
}
func ParseLLDPToStruct(lldpLayer gopacket.Layer, lldpLayerInfo gopacket.Layer) SwitchData {
	lldp, _ := lldpLayer.(*layers.LinkLayerDiscovery)
	lldpInfo, _ := lldpLayerInfo.(*layers.LinkLayerDiscoveryInfo)

	data := SwitchData{
		Protocol:    "LLDP",
		SwitchName:  lldpInfo.SysName,
		Interface:   string(lldp.PortID.ID),
		VLAN:        "[fail]",
		SwitchModel: "[fail]",
		VTPDomain:   ParseLLDPManagementIP(lldpInfo.MgmtAddress.Address),
	}
	for _, val := range lldpInfo.OrgTLVs {
		if val.SubType == 1 && val.OUI == layers.IEEEOUI8021 {
			data.VLAN = fmt.Sprint(binary.BigEndian.Uint16(val.Info))
		}
		/*if val.SubType == 3 && val.OUI == layers.IEEEOUI8021 {
			data.VLANName = string(val.Info)
		}*/
		if val.SubType == 10 && val.OUI == layers.IEEEOUIMedia {
			data.SwitchModel = string(val.Info)
		}
	}
	return data
}
func ParseLLDPManagementIP(addr []byte) string {
	var ip string
	if len(addr) == 4 {
		ip = fmt.Sprint(addr[0])
		for _, octet := range addr[1:] {
			ip += "." + fmt.Sprint(octet)
		}
	} else {
		ip = "0.0.0.0"
	}
	return ip
}
func FindNetworkDevice() (bool, string) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		color.Red("no devices found: MUST HAVE RELEVANT PACKET CAPTURE LIBRARY INSTALLED. In some environments you may need to run the program as admin/sudo. Pass -h for help text")
		color.Red(err.Error())
		os.Exit(1)
	}

	sort.Slice(devices, func(i, j int) bool {
		return devices[i].Name < devices[j].Name
	})

	if *listAdaptors {
		interfaceprint.PrintInterfaces(devices)
		return false, ""
	}

	found := false
	var devName string = ""

	if *nicIndex != 9999 {
		if *nicIndex < len(devices) {
			devName = devices[*nicIndex].Name
			found = true
			return found, devName
		}
	}

	if *nicName != "" {
		for _, device := range devices {
			if strings.Contains(device.Name, *nicName) {
				found = true
				devName = device.Name
				return found, devName
			}
			if strings.Contains(device.Description, *nicName) {
				found = true
				devName = device.Name
				break
			}
		}
	}
	return found, devName
}
func WriteSwitchDataStructAsJson(data SwitchData) error {
	jsonData, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return err
	}

	if *outFile == "" {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		err = os.WriteFile(dir+"/switch-data.json", jsonData, 0644)

		if err != nil {
			return err
		}
		return nil
	}
	err = os.WriteFile(*outFile, jsonData, 0644)
	if err != nil {
		return err
	}
	return nil
}
func PrintVersionBanner() {
	color.Yellow(" _     __________________    | " + blurb)
	color.Yellow("| | __| |___  ____/_  __ \\   |")
	color.Yellow("| |/ _` |__  / __ _  / / /   | " + repoString)
	color.Yellow("| | (_| | / /_/ / / /_/ /    | " + kofi)
	color.Yellow("|_|\\__,_| \\____/  \\____/     | " + versionString)
	os.Exit(0)
}
