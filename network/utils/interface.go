package utils

import (
	"fmt"
	"net"
	"slices"

	"github.com/google/gopacket/pcap"
)

// FindInterfaceForAddr finds the appropriate network interface for a target address
func FindInterfaceForAddr(target string) (*pcap.Interface, error) {
	targetIP, targetNet, err := ParseIPOrCIDR(target)
	if err != nil {
		return nil, fmt.Errorf("target address parsing failed: %w", err)
	}

	ifaces, err := GetActiveInterfaces()
	if err != nil {
		return nil, fmt.Errorf("active interface lookup failed: %w", err)
	}

	filtered := filterInterfaces(ifaces)
	if len(filtered) == 0 {
		return nil, fmt.Errorf("no suitable interfaces available")
	}

	// Find interface containing target IP/subnet
	for _, iface := range filtered {
		for _, addr := range iface.Addresses {
			ipNet := &net.IPNet{IP: addr.IP, Mask: addr.Netmask}

			if targetNet != nil {
				if AreSubnetsOverlapping(targetNet, ipNet) {
					return &iface, nil
				}
			} else if ipNet.Contains(targetIP) {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("no interface found for target: %s", target)
}

// GetActiveInterfaces returns interfaces that are up
func GetActiveInterfaces() ([]pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("PCAP device enumeration failed: %w", err)
	}

	active := make([]pcap.Interface, 0, len(devices))
	for _, device := range devices {
		// Check if interface is up (0x2 flag)
		if device.Flags&0x2 != 0 {
			active = append(active, device)
		}
	}

	return active, nil
}

// GetInterfaceIPv4NetInfo returns IPv4 address and netmask for an interface
func GetInterfaceIPv4NetInfo(iface *pcap.Interface) (net.IP, net.IPMask, error) {
	for _, addr := range iface.Addresses {
		if ip := addr.IP.To4(); ip != nil {
			return ip, addr.Netmask, nil
		}
	}
	return nil, nil, fmt.Errorf("interface %s has no IPv4 addresses", iface.Name)
}

// filterInterfaces removes loopback and inactive interfaces
func filterInterfaces(interfaces []pcap.Interface) []pcap.Interface {
	filtered := make([]pcap.Interface, 0, len(interfaces))
	for _, iface := range interfaces {
		// Skip loopback (0x1) interfaces
		if iface.Flags&0x1 != 0 {
			continue
		}
		filtered = append(filtered, iface)
	}
	return filtered
}

type sysIfaceInfo struct {
	ips []net.IP
	mac net.HardwareAddr
}

// GetInterfaceMAC retrieves MAC address for a pcap interface
func GetInterfaceMAC(pcapName string) (net.HardwareAddr, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("PCAP device enumeration failed: %w", err)
	}

	// Find device by name
	idx := slices.IndexFunc(devices, func(d pcap.Interface) bool { return d.Name == pcapName })
	if idx == -1 {
		return nil, fmt.Errorf("device not found: %s", pcapName)
	}
	device := devices[idx]

	// Get system interfaces
	sysIfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("system interface enumeration failed: %w", err)
	}

	// Build IP-to-interface mapping
	sysInfo := make(map[string]sysIfaceInfo)
	for _, iface := range sysIfaces {
		addrs, err := iface.Addrs()
		if err != nil || iface.HardwareAddr == nil {
			continue
		}

		ips := make([]net.IP, 0, len(addrs))
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				ips = append(ips, ipNet.IP)
			}
		}
		sysInfo[iface.Name] = sysIfaceInfo{ips: ips, mac: iface.HardwareAddr}
	}

	// Try direct name match first
	if info, exists := sysInfo[device.Name]; exists {
		return info.mac, nil
	}

	// Fallback to IP matching
	deviceIPs := make([]net.IP, len(device.Addresses))
	for i, addr := range device.Addresses {
		deviceIPs[i] = addr.IP
	}

	for _, info := range sysInfo {
		if ipSetEqual(deviceIPs, info.ips) {
			return info.mac, nil
		}
	}

	return nil, fmt.Errorf("no MAC found for device: %s", pcapName)
}

// Helper types and functions
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
