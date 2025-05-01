//go:build darwin

package interfaceprint

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/google/gopacket/pcap"
)

func PrintInterfaces(nics []pcap.Interface) (bool, string) {
	color.Cyan("devices: ")
	header := fmt.Sprintf("%11s %20s", "name", "IP")
	color.Cyan(header)
	for i, dev := range nics {
		switch len(dev.Addresses) {
		case 0:
			line := fmt.Sprintf("%-6s %-20s | %-25s", "["+fmt.Sprint(i)+"]", dev.Name, "")
			color.Cyan(line)
		case 1:
			line := fmt.Sprintf("%-6s %-20s | %-25s", "["+fmt.Sprint(i)+"]", dev.Name, dev.Addresses[0].IP.String())
			color.Cyan(line)
		case 2:
			line := fmt.Sprintf("%-6s %-20s | %-25s", "["+fmt.Sprint(i)+"]", dev.Name, dev.Addresses[1].IP.String())
			color.Cyan(line)
		case 3:
			line := fmt.Sprintf("%-6s %-20s | %-25s", "["+fmt.Sprint(i)+"]", dev.Name, dev.Addresses[0].IP.String())
			color.Cyan(line)
		}
	}
	return false, ""
}
