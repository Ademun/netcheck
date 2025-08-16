package discovery

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
)

func serializeLayers(layers ...gopacket.SerializableLayer) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, layers...); err != nil {
		return nil, fmt.Errorf("layer serialization failed: %w", err)
	}
	return buf.Bytes(), nil
}

func extractMAC(host []*Host) (net.HardwareAddr, error) {
	split := strings.Split(host[0].Info, " ")
	macString := split[len(split)-1]
	mac, err := net.ParseMAC(macString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MAC address: %w", err)
	}
	return mac, nil
}
