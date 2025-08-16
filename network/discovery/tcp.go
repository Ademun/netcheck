package discovery

import (
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/ademun/netcheck/network/utils"
	"github.com/ademun/netcheck/structs"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	TcpDiscoverSyn = iota
	TcpDiscoverAck
)

const (
	defaultDstPort = 80
	defaultSrcPort = 80
)

type TcpDiscoverer struct {
	baseDiscoverer
	tcpFlag int
}

func NewTcpDiscoverer(tcpFlag int) *TcpDiscoverer {
	return &TcpDiscoverer{
		baseDiscoverer: baseDiscoverer{
			interPacketDelay: 2 * time.Millisecond,
			finalDelay:       5 * time.Second,
			maxRetries:       2,
		},
		tcpFlag: tcpFlag,
	}
}

func (d *TcpDiscoverer) Discover(ips []net.IP) ([]*Host, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs provided")
	}

	diskSetup, err := getDiscoverySetup(ips[0])
	if err != nil {
		return nil, err
	}
	defer diskSetup.handle.Close()

	gatewayMAC, err := getGatewayMAC(diskSetup.gatewayIP)
	if err != nil {
		return nil, fmt.Errorf("gateway MAC resolution failed: %w", err)
	}

	packetSource, err := utils.PcapListenPackets(diskSetup.handle, "tcp")
	if err != nil {
		return nil, fmt.Errorf("packet listener failed: %w", err)
	}

	parseFunc := func(p gopacket.Packet) *Host {
		return parseTCPPacket(p, ips)
	}

	hostChan := processPackets(packetSource.Packets(), parseFunc)
	available := structs.NewSet[string]()
	results := make([]*Host, 0)
	wg := &sync.WaitGroup{}
	wg.Add(1)

	go collectResults(hostChan, &results, available, wg)

	createPacket := func(ip net.IP) ([]byte, error) {
		return CreateTCPPacket(
			diskSetup.srcMAC,
			gatewayMAC,
			diskSetup.srcIP,
			ip,
			d.tcpFlag,
		)
	}

	if err := d.sendPackets(diskSetup.handle, ips, available, createPacket); err != nil {
		return nil, err
	}

	diskSetup.handle.Close()
	wg.Wait()
	sortResults(results)
	return results, nil
}

func getGatewayMAC(gateway net.IP) (net.HardwareAddr, error) {
	discoverer := NewArpDiscoverer()
	gatewayHost, err := discoverer.Discover([]net.IP{gateway})
	if err != nil || len(gatewayHost) == 0 {
		return nil, fmt.Errorf("gateway discovery failed")
	}
	return extractMAC(gatewayHost)
}

func parseTCPPacket(packet gopacket.Packet, ips []net.IP) *Host {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}

	tcp := tcpLayer.(*layers.TCP)
	if !tcp.ACK {
		return nil
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ipv4 := ipLayer.(*layers.IPv4)

	if !slices.ContainsFunc(ips, func(ip net.IP) bool {
		return ip.Equal(ipv4.SrcIP)
	}) {
		return nil
	}

	return &Host{
		IP:   ipv4.SrcIP,
		RTT:  time.Since(packet.Metadata().Timestamp),
		Info: fmt.Sprintf("Responded port: %d", tcp.DstPort),
	}
}

func CreateTCPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, tcpFlag int) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      128,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	var isSyn, isAck bool
	switch tcpFlag {
	case TcpDiscoverSyn:
		isSyn = true
	case TcpDiscoverAck:
		isAck = true
	default:
		return nil, fmt.Errorf("invalid tcp flag: %d", tcpFlag)
	}

	tcp := &layers.TCP{
		SrcPort: defaultSrcPort,
		DstPort: defaultDstPort,
		SYN:     isSyn,
		ACK:     isAck,
		Window:  14600,
	}

	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, fmt.Errorf("checksum layer failed: %w", err)
	}

	return serializeLayers(eth, ip, tcp, gopacket.Payload(nil))
}
