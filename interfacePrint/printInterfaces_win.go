//go:build windows

package interfaceprint

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/google/gopacket/pcap"
)

func PrintInterfaces(nics []pcap.Interface) (bool, string) {
	color.Cyan("devices: ")
	header := fmt.Sprintf("%10s %54s %31s", "name", "IP", "description")
	color.Cyan(header)
	for i, dev := range nics {
		switch len(dev.Addresses) {
		case 0:
			line := fmt.Sprintf("%-5s %-54s | %-20s | %-20s", "["+fmt.Sprint(i)+"]", dev.Name, "", dev.Description)
			color.Cyan(line)
		case 1:
			line := fmt.Sprintf("%-5s %-54s | %-20s | %-20s", "["+fmt.Sprint(i)+"]", dev.Name, dev.Addresses[0].IP.String(), dev.Description)
			color.Cyan(line)
		case 2:
			line := fmt.Sprintf("%-5s %-54s | %-20s | %-20s", "["+fmt.Sprint(i)+"]", dev.Name, dev.Addresses[1].IP.String(), dev.Description)
			color.Cyan(line)
		}
	}
	return false, ""
}
