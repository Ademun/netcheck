package discovery

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/ademun/netcheck/network/routing"
	"github.com/ademun/netcheck/network/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TcpDiscoverer struct {
	interPacketDelay time.Duration
	finalDelay       time.Duration
	maxRetries       int
}

func NewTcpDiscoverer() *TcpDiscoverer {
	return &TcpDiscoverer{
		interPacketDelay: time.Millisecond * 1,
		finalDelay:       time.Second * 2,
		maxRetries:       2,
	}
}

func (d TcpDiscoverer) Discover(ips []net.IP) ([]*Host, error) {
	rtable, err := routing.GetRoutingTable()
	if err != nil {
		return nil, fmt.Errorf("failed to get routing table: %w", err)
	}

	route := routing.FindRoute(ips[0], rtable)
	if route == nil {
		return nil, errors.New("no route found for target IP")
	}

	discoverer := NewArpDiscoverer()
	gateway, err := discoverer.Discover([]net.IP{route.Gateway})
	if err != nil || len(gateway) == 0 {
		return nil, fmt.Errorf("failed to discover gateway MAC: %w", err)
	}

	gatewayMAC, err := extractMAC(gateway)
	if err != nil {
		return nil, fmt.Errorf("failed to extract host MAC: %w", err)
	}

	pcapIface, err := utils.SysToPcap(route.Iface)
	if err != nil {
		return nil, fmt.Errorf("interface conversion failed: %w", err)
	}

	ifaceIP, _, err := utils.GetPcapInterfaceIPv4NetInfo(pcapIface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface IP info: %w", err)
	}

	handle, err := utils.OpenPCAPHandle(pcapIface.Name, false)
	if err != nil {
		return nil, fmt.Errorf("pcap handle open failed: %w", err)
	}
	defer handle.Close()

	packetSource, err := utils.PcapListenPackets(handle, "tcp")
	if err != nil {
		return nil, fmt.Errorf("packet listener failed: %w", err)
	}

	hostChan := processTcpPackets(packetSource.Packets(), ips)
	results := make([]*Host, 0)
	statusMap := sync.Map{}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for host := range hostChan {
			if _, found := statusMap.LoadOrStore(host.IP.String(), true); !found {
				results = append(results, host)
			}
		}
	}()

	for range d.maxRetries {
		for _, ip := range ips {
			if _, responded := statusMap.Load(ip.String()); responded {
				continue
			}

			packet, err := createTCPPacket(route.Iface.HardwareAddr, gatewayMAC, ifaceIP, ip)
			if err != nil {
				continue
			}

			if err := utils.PcapSendPacket(handle, packet); err != nil {
				return nil, fmt.Errorf("ARP packet send failed: %w", err)
			}
			time.Sleep(d.interPacketDelay)
		}
		time.Sleep(d.finalDelay)
	}
	handle.Close()

	wg.Wait()
	sortResults(results)
	return results, nil
}

func processTcpPackets(packets <-chan gopacket.Packet, ips []net.IP) <-chan *Host {
	hosts := make(chan *Host)
	sem := make(chan struct{}, maxProcs)

	go func() {
		for packet := range packets {
			sem <- struct{}{}
			go func(p gopacket.Packet) {
				if host := parseTCPPacket(p, ips); host != nil {
					hosts <- host
				}
				<-sem
			}(packet)
		}
		close(hosts)
	}()

	return hosts
}

func parseTCPPacket(packet gopacket.Packet, ips []net.IP) *Host {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	tcpLr := tcpLayer.(*layers.TCP)
	if !tcpLr.ACK {
		return nil
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ipLr := ipLayer.(*layers.IPv4)

	if !slices.ContainsFunc(ips, func(ip net.IP) bool {
		return ip.Equal(ipLr.SrcIP)
	}) {
		return nil
	}

	return &Host{
		IP:   ipLr.SrcIP,
		RTT:  time.Since(packet.Metadata().Timestamp),
		Info: fmt.Sprintf("Responded port: %d", tcpLr.DstPort),
	}
}

func createTCPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) ([]byte, error) {
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

	tcp := &layers.TCP{
		SrcPort: defaultSrcPort,
		DstPort: defaultDstPort,
		SYN:     true,
		Window:  14600,
	}

	err := tcp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		return nil, fmt.Errorf("TCP packet creation failed: %w", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	payload := []byte{}

	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("ARP packet creation failed: %w", err)
	}
	return buf.Bytes(), nil
}
