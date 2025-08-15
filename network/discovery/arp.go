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

func (A ArpDiscoverer) Discover(ips []net.IP) ([]*Host, error) {
	results := make([]*Host, 0)

	rtable, err := routing.GetRoutingTable()
	if err != nil {
		return nil, err
	}

	route := routing.FindRoute(ips[0], rtable)
	if route == nil {
		return nil, errors.New("no route found")
	}

	pcapIface, err := utils.SysToPcap(route.Iface)
	if err != nil {
		return nil, err
	}

	ifaceIP, _, err := utils.GetInterfaceIPv4NetInfo(pcapIface)
	if err != nil {
		return nil, err
	}

	handle, err := utils.OpenPCAPHandle(pcapIface.Name)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	packets, err := utils.PcapListenPackets(handle, buildFilter(ifaceIP, route.Iface.HardwareAddr))
	if err != nil {
		return nil, err
	}

	receive := processPackets(packets.Packets())

	statusMap := sync.Map{}
	for _, ip := range ips {
		statusMap.Store(ip.String(), false)
	}

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		for data := range receive {
			if status, ok := statusMap.Load(data.IP.String()); ok {
				if !status.(bool) {
					statusMap.Swap(data.IP.String(), true)
					results = append(results, data)
				}
			}
		}
		wg.Done()
	}()

	for range A.maxRetries {
		for _, ip := range ips {
			if status, ok := statusMap.Load(ip.String()); ok {
				if status.(bool) {
					continue
				}
			}
			packet, err := createARPPacket(route.Iface.HardwareAddr, ifaceIP, ip)
			if err != nil {
				continue
			}

			err = utils.PcapSendPacket(handle, packet)
			if err != nil {
				return nil, err
			}
			time.Sleep(A.interPacketDelay)
		}
		time.Sleep(A.finalDelay)
	}
	handle.Close()

	wg.Wait()

	results = append(results, &Host{
		IP:   ifaceIP,
		RTT:  0,
		Info: fmt.Sprintf("HW address: %s", route.Iface.HardwareAddr),
	})

	sort.Slice(results, func(i, j int) bool {
		return bytes.Compare(results[i].IP, results[j].IP) < 0
	})

	return results, nil
}

func buildFilter(ifaceIP net.IP, ifaceMAC net.HardwareAddr) string {
	return fmt.Sprintf("arp && dst host %s && ether dst %s", ifaceIP.String(), ifaceMAC.String())
}

func processPackets(packets <-chan gopacket.Packet) <-chan *Host {
	results := make(chan *Host)
	sem := make(chan struct{}, maxProcs)

	go func() {
		for packet := range packets {
			sem <- struct{}{}
			go func() {
				host := processARPPacket(packet)
				if host != nil {
					results <- host
				}
				<-sem
			}()
		}
		close(sem)
		close(results)
	}()

	return results
}

func processARPPacket(packet gopacket.Packet) *Host {
	ARPLayer := packet.Layer(layers.LayerTypeARP)
	if ARPLayer == nil {
		return nil
	}

	ARP := ARPLayer.(*layers.ARP)

	if ARP.Operation != layers.ARPReply {
		return nil
	}

	return &Host{
		IP:   ARP.SourceProtAddress,
		RTT:  time.Since(packet.Metadata().Timestamp),
		Info: fmt.Sprintf("HW address: %s", net.HardwareAddr(ARP.SourceHwAddress).String()),
	}
}

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
