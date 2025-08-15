package discovery

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/ademun/netcheck/network/routing"
	"github.com/ademun/netcheck/network/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	maxProcs = 10
)

type ArpDiscoverer struct {
	interPacketDelay time.Duration
	finalDelay       time.Duration
	maxRetries       int
}

func NewArpDiscoverer() *ArpDiscoverer {
	return &ArpDiscoverer{
		interPacketDelay: time.Millisecond * 8,
		finalDelay:       time.Second * 2,
		maxRetries:       2,
	}
}

func (d ArpDiscoverer) Discover(ips []net.IP) ([]*Host, error) {
	rtable, err := routing.GetRoutingTable()
	if err != nil {
		return nil, fmt.Errorf("failed to get routing table: %w", err)
	}

	route := routing.FindRoute(ips[0], rtable)
	if route == nil {
		return nil, errors.New("no route found for target IP")
	}

	pcapIface, err := utils.SysToPcap(route.Iface)
	if err != nil {
		return nil, fmt.Errorf("interface conversion failed: %w", err)
	}

	ifaceIP, _, err := utils.GetPcapInterfaceIPv4NetInfo(pcapIface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface IP info: %w", err)
	}

	handle, err := utils.OpenPCAPHandle(pcapIface.Name)
	if err != nil {
		return nil, fmt.Errorf("pcap handle open failed: %w", err)
	}
	defer handle.Close()

	filter := buildFilter(ifaceIP, route.Iface.HardwareAddr)
	packetSource, err := utils.PcapListenPackets(handle, filter)
	if err != nil {
		return nil, fmt.Errorf("packet listener failed: %w", err)
	}

	// Process incoming ARP replies
	hostChan := processPackets(packetSource.Packets())
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

			packet, err := createARPPacket(route.Iface.HardwareAddr, ifaceIP, ip)
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

	// Add local interface to results
	results = append(results, &Host{
		IP:   ifaceIP,
		RTT:  0,
		Info: fmt.Sprintf("HW address: %s", route.Iface.HardwareAddr),
	})

	wg.Wait()
	sortResults(results)
	return results, nil
}

func buildFilter(ifaceIP net.IP, ifaceMAC net.HardwareAddr) string {
	return fmt.Sprintf("arp && dst host %s && ether dst %s", ifaceIP.String(), ifaceMAC.String())
}

func processPackets(packets <-chan gopacket.Packet) <-chan *Host {
	hosts := make(chan *Host)
	sem := make(chan struct{}, maxProcs)

	go func() {
		for packet := range packets {
			sem <- struct{}{}
			go func(p gopacket.Packet) {
				if host := parseARPPacket(p); host != nil {
					hosts <- host
				}
				<-sem
			}(packet)
		}
		close(hosts)
	}()

	return hosts
}

func parseARPPacket(packet gopacket.Packet) *Host {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return nil
	}

	arp := arpLayer.(*layers.ARP)
	if arp.Operation != layers.ARPReply {
		return nil
	}

	return &Host{
		IP:   arp.SourceProtAddress,
		RTT:  time.Since(packet.Metadata().Timestamp),
		Info: fmt.Sprintf("HW address: %s", net.HardwareAddr(arp.SourceHwAddress)),
	}
}

func createARPPacket(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      make([]byte, 6),
		DstProtAddress:    dstIP.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
		return nil, fmt.Errorf("ARP packet creation failed: %w", err)
	}
	return buf.Bytes(), nil
}

func sortResults(hosts []*Host) {
	sort.Slice(hosts, func(i, j int) bool {
		return bytes.Compare(hosts[i].IP, hosts[j].IP) < 0
	})
}
