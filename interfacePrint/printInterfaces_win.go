//go:build windows

package interfaceprint

import (
	"fmt"

	"github.com/BadPixel89/colourtext"
	"github.com/google/gopacket/pcap"
)

func PrintInterfaces(nics []pcap.Interface) (bool, string) {
	colourtext.PrintInfo("devices: ")
	header := fmt.Sprintf("%10s %54s %31s", "name", "IP", "description")
	colourtext.PrintColour(colourtext.Cyan, header)
	for i, dev := range nics {
		switch len(dev.Addresses) {
		case 0:
			line := fmt.Sprintf("%-5s %-54s | %-20s | %-20s", "["+fmt.Sprint(i)+"]", dev.Name, "", dev.Description)
			colourtext.PrintColour(colourtext.Cyan, line)
		case 1:
			line := fmt.Sprintf("%-5s %-54s | %-20s | %-20s", "["+fmt.Sprint(i)+"]", dev.Name, "", dev.Description)
			colourtext.PrintColour(colourtext.Cyan, line)
		case 2:
			line := fmt.Sprintf("%-5s %-54s | %-20s | %-20s", "["+fmt.Sprint(i)+"]", dev.Name, dev.Addresses[1].IP.String(), dev.Description)
			//line := "[" + fmt.Sprint(i) + "] " + dev.Name + " | " + dev.Description + " | " + dev.Addresses[1].IP.String()
			colourtext.PrintColour(colourtext.Cyan, line)
		}
	}
	return false, ""
}
