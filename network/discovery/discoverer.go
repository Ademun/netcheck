package discovery

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/ademun/netcheck/network/routing"
	"github.com/ademun/netcheck/network/utils"
	"github.com/ademun/netcheck/structs"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	maxProcs       = 10
	defaultDstPort = 80
	defaultSrcPort = 443
)

type baseDiscoverer struct {
	interPacketDelay time.Duration
	finalDelay       time.Duration
	maxRetries       int
}

type discoverySetup struct {
	srcIP     net.IP
	srcMAC    net.HardwareAddr
	gatewayIP net.IP
	handle    *pcap.Handle
}

type packetProcessor func(packet gopacket.Packet) *Host
type packetCreator func(dstIP net.IP) ([]byte, error)

func getDiscoverySetup(networkIP net.IP) (*discoverySetup, error) {
	rtable, err := routing.GetRoutingTable()
	if err != nil {
		return nil, fmt.Errorf("failed to get routing table: %w", err)
	}
	route := routing.FindRoute(networkIP, rtable)
	if route == nil {
		return nil, fmt.Errorf("failed to find route for target %s", networkIP.String())
	}
	pcapIface, err := utils.SysToPcap(route.Iface)
	if err != nil {
		return nil, fmt.Errorf("interface conversion failed: %w", err)
	}
	ifaceIP, _, err := utils.GetPcapInterfaceIPv4NetInfo(pcapIface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface ipv4 info: %w", err)
	}
	handle, err := utils.OpenPCAPHandle(pcapIface.Name, false)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}
	return &discoverySetup{
		srcIP:     ifaceIP,
		srcMAC:    route.Iface.HardwareAddr,
		gatewayIP: route.Gateway,
		handle:    handle,
	}, nil
}

func processPackets(packets <-chan gopacket.Packet, parseFunc packetProcessor) <-chan *Host {
	hosts := make(chan *Host)
	sem := make(chan struct{}, maxProcs)

	go func() {
		defer close(hosts)
		for packet := range packets {
			sem <- struct{}{}
			go func(p gopacket.Packet) {
				if host := parseFunc(p); host != nil {
					hosts <- host
				}
				<-sem
			}(packet)
		}
	}()

	return hosts
}

func collectResults(hosts <-chan *Host, results *[]*Host, availableHosts *structs.Set[string], wg *sync.WaitGroup) {
	defer wg.Done()
	for host := range hosts {
		if !availableHosts.Contains(host.IP.String()) {
			*results = append(*results, host)
			availableHosts.Add(host.IP.String())
		}
	}
}

func (d *baseDiscoverer) sendPackets(handle *pcap.Handle, ips []net.IP, availableHosts *structs.Set[string], createPacketFunc packetCreator) error {
	for range d.maxRetries {
		for _, ip := range ips {
			if availableHosts.Contains(ip.String()) {
				continue
			}

			packet, err := createPacketFunc(ip)
			if err != nil {
				continue
			}

			if err := handle.WritePacketData(packet); err != nil {
				return fmt.Errorf("error writing packet data: %w", err)
			}
			time.Sleep(d.interPacketDelay)
		}
		time.Sleep(d.finalDelay)
	}
	return nil
}

type Host struct {
	IP   net.IP
	RTT  time.Duration
	Info string
}

func (h Host) String() string {
	return fmt.Sprintf("IP: %s\nRTT: %s\nInfo: %q\n", h.IP, h.RTT, h.Info)
}

type Discoverer interface {
	Discover([]net.IP) ([]*Host, error)
}

func sortResults(hosts []*Host) {
	sort.Slice(hosts, func(i, j int) bool {
		return bytes.Compare(hosts[i].IP, hosts[j].IP) < 0
	})
}
