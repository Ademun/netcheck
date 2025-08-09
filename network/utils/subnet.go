package utils

import (
	"fmt"
	"net"
	"strings"
)

func HostsFromSubnet(targetCIDR string) ([]net.IP, error) {
	targetIp, targetNet, err := net.ParseCIDR(targetCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %q", err)
	}
	ips := make([]net.IP, 0)
	for ip := targetIp.Mask(targetNet.Mask); targetNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, net.ParseIP(ip.String()))
	}
	return ips[1 : len(ips)-1], nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ParseTargetAddress(target string) (net.IP, *net.IPNet, error) {
	if strings.Contains(target, "/") {
		ip, subnet, err := net.ParseCIDR(target)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid CIDR: %q", err)
		}
		return ip, subnet, nil
	}

	ip := net.ParseIP(target)
	if ip == nil {
		return nil, nil, fmt.Errorf("invalid IP address: %q", target)
	}
	return ip, nil, nil
}

func AreSubnetsOverlapping(net1, net2 *net.IPNet) bool {
	return net1.Contains(net2.IP) || net2.Contains(net1.IP)
}

func BroadcastIPv4Address(ip net.IP, mask net.IPMask) net.IP {
	ip = ip.To4()
	if ip == nil {
		return nil
	}

	network := make(net.IP, len(ip))
	for i := range ip {
		network[i] = ip[i] & mask[i]
	}

	broadcast := make(net.IP, len(ip))
	for i := range network {
		broadcast[i] = network[i] | ^mask[i]
	}

	return broadcast
}
