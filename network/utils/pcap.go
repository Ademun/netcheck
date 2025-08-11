package utils

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

// OpenPCAPHandle creates a raw packet capture handle on
func OpenPCAPHandle(iface string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(
		iface,
		1600, // Snaplen
		true, // Promiscuous mode
		pcap.BlockForever,
	)

	if err != nil {
		return nil, fmt.Errorf("pcap open failed: %w", err)
	}

	return handle, nil
}
