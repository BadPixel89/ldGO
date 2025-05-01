//go:build linux

package interfaceprint

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/google/gopacket/pcap"
)

func PrintInterfaces(nics []pcap.Interface) (bool, string) {
	color.Cyan("devices:")
	header := fmt.Sprintf("%11s %20s %36s", "name", "IP", "description")
	color.Cyan(header)
	for i, dev := range nics {
		switch len(dev.Addresses) {
		case 0:
			line := fmt.Sprintf("%-6s %-20s | %-25s | %-33s", "["+fmt.Sprint(i)+"]", dev.Name, "", dev.Description)
			color.Cyan(line)
		case 1:
			line := fmt.Sprintf("%-6s %-20s | %-25s | %-33s", "["+fmt.Sprint(i)+"]", dev.Name, dev.Addresses[0].IP.String(), dev.Description)
			color.Cyan(line)
		case 2:
			line := fmt.Sprintf("%-6s %-20s | %-25s | %-33s", "["+fmt.Sprint(i)+"]", dev.Name, dev.Addresses[0].IP.String(), dev.Description)
			color.Cyan(line)
		}
	}
	return false, ""
}
