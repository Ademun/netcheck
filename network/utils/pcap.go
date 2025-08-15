package utils

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// OpenPCAPHandle creates a raw packet capture handle on
func OpenPCAPHandle(iface string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(
		iface,
		6400, // Snaplen
		true, // Promiscuous mode
		pcap.BlockForever,
	)

	if err != nil {
		return nil, fmt.Errorf("pcap open failed: %w", err)
	}

	return handle, nil
}

func PcapListenPackets(handle *pcap.Handle, filter string) (*gopacket.PacketSource, error) {
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %s", err)
	}
	return gopacket.NewPacketSource(handle, handle.LinkType()), nil
}

func PcapSendPacket(handle *pcap.Handle, packet []byte) error {
	if err := handle.WritePacketData(packet); err != nil {
		return fmt.Errorf("pcap write failed: %w", err)
	}
	return nil
}
