package utils

import (
	"fmt"
	"net"
	"slices"

	"github.com/google/gopacket/pcap"
)

// GetPcapInterfaceIPv4NetInfo retrieves the first IPv4 address and netmask for a pcap interface
func GetPcapInterfaceIPv4NetInfo(iface *pcap.Interface) (net.IP, net.IPMask, error) {
	for _, addr := range iface.Addresses {
		if ip := addr.IP.To4(); ip != nil {
			return ip, addr.Netmask, nil
		}
	}
	return nil, nil, fmt.Errorf("no IPv4 address found for interface %s", iface.Name)
}

// GetSysInterfaceIPv4NetInfo retrieves the first IPv4 address and netmask for a system interface
func GetSysInterfaceIPv4NetInfo(iface *net.Interface) (net.IP, net.IPMask, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get addresses for %s: %w", iface.Name, err)
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			return ipNet.IP, ipNet.Mask, nil
		}
	}
	return nil, nil, fmt.Errorf("no IPv4 address found for interface %s", iface.Name)
}

// PcapToSys converts pcap interface to system interface by:
// 1. Direct name matching
// 2. IP address set comparison
func PcapToSys(pcapIface *pcap.Interface) (*net.Interface, error) {
	sysIfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("system interface enumeration failed: %w", err)
	}

	// First pass: match by interface name
	for _, iface := range sysIfaces {
		if iface.Name == pcapIface.Name {
			return &iface, nil
		}
	}

	// Second pass: match by IP address set
	pcapIPs := extractPcapIPs(pcapIface)
	for _, iface := range sysIfaces {
		sysIPs, err := extractSysIPs(&iface)
		if err != nil {
			continue // Skip interfaces with address errors
		}
		if ipSetEqual(pcapIPs, sysIPs) {
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("no matching system interface found for %s", pcapIface.Name)
}

// SysToPcap converts system interface to pcap interface using:
// 1. Direct name matching
// 2. IP address set comparison
func SysToPcap(sysIface *net.Interface) (*pcap.Interface, error) {
	pcapIfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("pcap device enumeration failed: %w", err)
	}

	// First pass: match by interface name
	for _, iface := range pcapIfaces {
		if iface.Name == sysIface.Name {
			return &iface, nil
		}
	}

	// Second pass: match by IP address set
	sysIPs, err := extractSysIPs(sysIface)
	if err != nil {
		return nil, fmt.Errorf("failed to get IPs for %s: %w", sysIface.Name, err)
	}

	for _, iface := range pcapIfaces {
		pcapIPs := extractPcapIPs(&iface)
		if ipSetEqual(sysIPs, pcapIPs) {
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("no matching pcap interface found for %s", sysIface.Name)
}

// extractPcapIPs collects all IPs from pcap interface addresses
func extractPcapIPs(p *pcap.Interface) []net.IP {
	ips := make([]net.IP, len(p.Addresses))
	for i, addr := range p.Addresses {
		ips[i] = addr.IP
	}
	return ips
}

// extractSysIPs collects all IPs from system interface
func extractSysIPs(iface *net.Interface) ([]net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			ips = append(ips, ipNet.IP)
		}
	}
	return ips, nil
}

// ipSetEqual compares two IP sets ignoring order
func ipSetEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for _, ipA := range a {
		if !slices.ContainsFunc(b, func(ipB net.IP) bool { return ipA.Equal(ipB) }) {
			return false
		}
	}
	return true
}
