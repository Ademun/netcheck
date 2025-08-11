package discovery

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"github.com/ademun/netcheck/network/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ICMPv4Discoverer performs host discovery using ARP requests
type ICMPv4Discoverer struct {
	target  string // Target subnet in CIDR notation
	timeout time.Duration
}

func NewICMPv4Discoverer(target string, timeout time.Duration) *ICMPv4Discoverer {
	return &ICMPv4Discoverer{target: target, timeout: timeout}
}

// Discover sends ICMP requests to all hosts in the target subnet
func (i *ICMPv4Discoverer) Discover() ([]Host, error) {
	// Find network interface for target subnet
	iface, err := utils.FindInterfaceForAddr(i.target)
	if err != nil {
		return nil, fmt.Errorf("interface lookup failed: %w", err)
	}
	if iface == nil {
		return nil, fmt.Errorf("no suitable interface found for target: %s", i.target)
	}

	// Get interface IPv4 address and subnet mask
	ifaceIP, _, err := utils.GetInterfaceIPv4NetInfo(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface IP: %w", err)
	}

	// Get list of hosts in target subnet
	hosts, err := utils.GetHostsFromSubnet(i.target)
	if err != nil {
		return nil, fmt.Errorf("subnet hosts enumeration failed: %w", err)
	}

	// Create PCAP handle for packet transmission
	pcapHandle, err := utils.OpenPCAPHandle(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("packet socket creation failed: %w", err)
	}

	// Get interface MAC address
	ifaceMAC, err := utils.GetInterfaceMAC(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("MAC address retrieval failed: %w", err)
	}

	results := make(chan Host)
	ctx, cancel := context.WithTimeout(context.Background(), i.timeout)
	defer cancel()

	hostMap := make(map[uint16]net.IP)
	go listenICMPv4(pcapHandle, ifaceIP, ifaceMAC, hostMap, results, ctx)

	// Send ICMP request to each host
	for _, targetIP := range hosts {
		packet, packetID, err := createICMPv4Packet(ifaceMAC, ifaceIP, targetIP)
		if err != nil {
			return nil, fmt.Errorf("ICMP packet creation failed: %w", err)
		}

		hostMap[*packetID] = targetIP

		if err := pcapHandle.WritePacketData(packet); err != nil {
			return nil, fmt.Errorf("packet transmission failed: %w", err)
		}
	}

	// Collect results
	availableHosts := make([]Host, 0)
	/*for host := range results {
		availableHosts = append(availableHosts, host)
	}*/

	return availableHosts, nil
}

// listen captures and processes ICMP replies
func listenICMPv4(handle *pcap.Handle, ifaceIP net.IP, ifaceMAC net.HardwareAddr, hostMap map[uint16]net.IP, results chan<- Host, ctx context.Context) {
	defer close(results)

	filter := "icmp"

	// Set filter to capture only ICMP packets
	if err := handle.SetBPFFilter(filter); err != nil {
		fmt.Printf("Warning: BPF filter setup failed: %v\n", err)
	}

	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case packet := <-packetSrc.Packets():
			fmt.Println("Packet!")
			processICMPv4Packet(packet, hostMap)
		case <-ctx.Done():
			return
		}
	}
}

// createICMPv4Packet constructs an ICMP request packet
func createICMPv4Packet(ifaceMAC net.HardwareAddr, ifaceIP, targetIP net.IP) ([]byte, *uint16, error) {
	// Ethernet layer (broadcast)
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       ifaceMAC,
		DstMAC:       net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// IPv4 layer
	IPv4Layer := &layers.IPv4{
		Version:  4,
		TTL:      128,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    ifaceIP,
		DstIP:    targetIP,
	}

	// ICMP layer (request for target IP)
	randomID := uint16(rand.Uint32())

	ICMPLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(1, 0),
		Id:       randomID,
		Seq:      0,
	}

	// Serialize packet
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buf := gopacket.NewSerializeBuffer()

	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(time.Now().UnixNano()))

	if err := gopacket.SerializeLayers(buf, options, ethernetLayer, IPv4Layer, ICMPLayer, gopacket.Payload(payload)); err != nil {
		return nil, nil, fmt.Errorf("packet serialization failed: %w", err)
	}

	return buf.Bytes(), &randomID, nil
}

func processICMPv4Packet(packet gopacket.Packet, hostMap map[uint16]net.IP) {
	ICMPLayer := packet.Layer(layers.LayerTypeICMPv4)
	if ICMPLayer == nil {
		return // Not an ICMP packet
	}

	ICMP := ICMPLayer.(*layers.ICMPv4)

	// Validate it's a reply
	if ICMP.TypeCode != layers.ICMPv4TypeEchoReply {
		return
	}

	if host, ok := hostMap[ICMP.Id]; ok {
		fmt.Println(host.String())
	}
}
