//go:build darwin

package interfaceprint

import (
	"fmt"

	"github.com/BadPixel89/colourtext"
	"github.com/google/gopacket/pcap"
)

func PrintInterfaces(nics []pcap.Interface) (bool, string) {
	colourtext.PrintInfo("devices: ")
	header := fmt.Sprintf("%11s %20s", "name", "IP")
	colourtext.PrintColour(colourtext.Cyan, header)
	for i, dev := range nics {
		switch len(dev.Addresses) {
		case 0:
			line := fmt.Sprintf("%-6s %-20s | %-25s", "["+fmt.Sprint(i)+"]", dev.Name, "")
			colourtext.PrintColour(colourtext.Cyan, line)
		case 1:
			line := fmt.Sprintf("%-6s %-20s | %-25s", "["+fmt.Sprint(i)+"]", dev.Name, dev.Addresses[0].IP.String())
			colourtext.PrintColour(colourtext.Cyan, line)
		case 2:
			line := fmt.Sprintf("%-6s %-20s | %-25s", "["+fmt.Sprint(i)+"]", dev.Name, dev.Addresses[1].IP.String())
			colourtext.PrintColour(colourtext.Cyan, line)
		case 3:
			line := fmt.Sprintf("%-6s %-20s | %-25s", "["+fmt.Sprint(i)+"]", dev.Name, dev.Addresses[0].IP.String())
			colourtext.PrintColour(colourtext.Cyan, line)
		}
	}
	return false, ""
}
