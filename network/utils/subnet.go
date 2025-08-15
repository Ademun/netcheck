package utils

import (
	"fmt"
	"net"
)

// GetHostsFromAddr enumerates all usable IPs in a subnet or a singular address
func GetHostsFromAddr(targetAddr string) ([]net.IP, error) {
	if ip := net.ParseIP(targetAddr); ip != nil {
		return []net.IP{ip}, nil
	}

	subnetIp, subnet, err := net.ParseCIDR(targetAddr)
	if err != nil {
		return nil, err
	}

	ips := make([]net.IP, 0)
	for ip := subnetIp.Mask(subnet.Mask); subnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, net.ParseIP(ip.String()))
	}

	ones, bits := subnet.Mask.Size()
	if bits == ones || bits-ones == 1 {
		return ips, nil
	}
	return ips[1 : len(ips)-1], nil
}

// Helper function to increment IP address
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ParseIPOrCIDR parses target IP or CIDR
func ParseIPOrCIDR(target string) (net.IP, *net.IPNet, error) {
	if ip := net.ParseIP(target); ip != nil {
		return ip, nil, nil
	}

	ip, subnet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid IP/CIDR format: %w", err)
	}
	return ip, subnet, nil
}

// AreSubnetsOverlapping checks if two subnets overlap
func AreSubnetsOverlapping(net1, net2 *net.IPNet) bool {
	return net1.Contains(net2.IP) || net2.Contains(net1.IP)
}

// BroadcastIPAddress return a broadcast address for a specified subnetwork
func BroadcastIPAddress(subnet *net.IPNet) net.IP {
	broadcast := make(net.IP, len(subnet.IP))
	for i := range subnet.IP {
		broadcast[i] = subnet.IP[i] | ^subnet.Mask[i]
	}

	return broadcast
}
