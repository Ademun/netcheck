package discovery

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/ademun/netcheck/network/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ARPDiscoverer performs host discovery using ARP requests
type ARPDiscoverer struct {
	target  string // Target subnet in CIDR notation
	timeout time.Duration
}

func NewARPDiscoverer(target string, timeout time.Duration) *ARPDiscoverer {
	return &ARPDiscoverer{target: target, timeout: timeout}
}

// Discover sends ARP requests to all hosts in the target subnet
func (a *ARPDiscoverer) Discover() ([]Host, error) {
	// Find network interface for target subnet
	iface, err := utils.FindInterfaceForAddr(a.target)
	if err != nil {
		return nil, fmt.Errorf("interface lookup failed: %w", err)
	}
	if iface == nil {
		return nil, fmt.Errorf("no suitable interface found for target: %s", a.target)
	}

	// Get interface IPv4 address and subnet mask
	ifaceIP, _, err := utils.GetInterfaceIPv4NetInfo(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface IP: %w", err)
	}

	// Get list of hosts in target subnet
	hosts, err := utils.GetHostsFromSubnet(a.target)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Listen for ARP packets
	go listenARP(pcapHandle, ifaceIP, ifaceMAC, results, ctx)

	// Collect results
	availableHosts := make([]Host, 0)
	go func() {
		for host := range results {
			availableHosts = append(availableHosts, host)
		}
	}()

	// Send ARP request to each host
	for _, targetIP := range hosts {
		packet, err := createARPPacket(ifaceMAC, ifaceIP, targetIP)
		if err != nil {
			return nil, fmt.Errorf("ARP packet creation failed: %w", err)
		}

		if err := pcapHandle.WritePacketData(packet[:42]); err != nil {
			return nil, fmt.Errorf("packet transmission failed: %w", err)
		}
		time.Sleep(time.Millisecond * 1)
	}

	time.Sleep(a.timeout)
	cancel()

	return availableHosts, nil
}

// listen captures and processes ARP replies
func listenARP(handle *pcap.Handle, ifaceIP net.IP, ifaceMAC net.HardwareAddr, results chan<- Host, ctx context.Context) {
	defer close(results)

	filter := fmt.Sprintf("arp && dst host %s && ether dst %s", ifaceIP.String(), ifaceMAC.String())

	// Set filter to capture only ARP packets
	if err := handle.SetBPFFilter(filter); err != nil {
		fmt.Printf("Warning: BPF filter setup failed: %v\n", err)
	}

	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	seen := make(map[string]struct{})

	for {
		select {
		case packet := <-packetSrc.Packets():
			host := processARPPacket(packet)
			if host != nil {
				if _, exists := seen[host.IP.String()]; !exists {
					results <- *host
					seen[host.IP.String()] = struct{}{}
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// createARPPacket constructs an ARP request packet
func createARPPacket(ifaceMAC net.HardwareAddr, ifaceIP, targetIP net.IP) ([]byte, error) {
	// Ethernet layer (broadcast)
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       ifaceMAC,
		DstMAC:       net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		EthernetType: layers.EthernetTypeARP,
	}

	// ARP layer (request for target IP)
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   ifaceMAC,
		SourceProtAddress: ifaceIP.To4(),
		DstHwAddress:      make([]byte, 6),
		DstProtAddress:    targetIP.To4(),
	}

	// Serialize packet
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buf := gopacket.NewSerializeBuffer()

	if err := gopacket.SerializeLayers(buf, options, ethernetLayer, arpLayer); err != nil {
		return nil, fmt.Errorf("packet serialization failed: %w", err)
	}

	return buf.Bytes(), nil
}

func processARPPacket(packet gopacket.Packet) *Host {

	ARPLayer := packet.Layer(layers.LayerTypeARP)
	if ARPLayer == nil {
		return nil // Not an ARP packet
	}

	ARP := ARPLayer.(*layers.ARP)

	// Validate it's a reply
	if ARP.Operation != layers.ARPReply {
		return nil
	}

	return &Host{
		IP:  net.IP(ARP.SourceProtAddress),
		MAC: net.HardwareAddr(ARP.SourceHwAddress),
	}
}
