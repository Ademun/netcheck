package discovery

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ademun/netcheck/network/utils"
	"github.com/ademun/netcheck/structs"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ArpDiscoverer struct {
	baseDiscoverer
}

func NewArpDiscoverer() *ArpDiscoverer {
	return &ArpDiscoverer{
		baseDiscoverer{
			interPacketDelay: 8 * time.Millisecond,
			finalDelay:       2 * time.Second,
			maxRetries:       2,
		},
	}
}

func (d ArpDiscoverer) Discover(ips []net.IP) ([]*Host, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs provided")
	}

	discSetup, err := getDiscoverySetup(ips[0])
	if err != nil {
		return nil, err
	}
	defer discSetup.handle.Close()

	packetSource, err := utils.PcapListenPackets(discSetup.handle, "arp")
	if err != nil {
		return nil, fmt.Errorf("packet listener failed: %w", err)
	}

	hostChan := processPackets(packetSource.Packets(), parseARPPacket)
	available := structs.NewSet[string]()
	results := make([]*Host, 0)
	wg := &sync.WaitGroup{}
	wg.Add(1)

	go collectResults(hostChan, &results, available, wg)

	createPacket := func(ip net.IP) ([]byte, error) {
		return createARPPacket(discSetup.srcMAC, discSetup.srcIP, ip)
	}

	if err := d.sendPackets(discSetup.handle, ips, available, createPacket); err != nil {
		return nil, err
	}

	discSetup.handle.Close()

	wg.Wait()
	results = append(results, createLocalHost(discSetup))
	sortResults(results)
	return results, nil
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

	return serializeLayers(eth, arp)
}

func createLocalHost(discSetup *discoverySetup) *Host {
	return &Host{
		IP:   discSetup.srcIP,
		RTT:  0,
		Info: fmt.Sprintf("HW address: %s", discSetup.srcMAC),
	}
}
