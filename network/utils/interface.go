package utils

import (
	"fmt"
	"net"
	"strings"
)

func FindInterfaceIdxForAddr(target string) (int, error) {
	targetIP, targetNet, err := parseTargetIP(target)
	if err != nil {
		return -1, err
	}
	ifaces, err := getActiveInterfaces()
	if err != nil {
		return -1, err
	}
	ifaces = filterInterfaces(ifaces)

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if targetNet != nil {
				if isSubnetOverlap(targetNet, ipNet) {
					fmt.Println(targetNet.String(), ipNet.String(), iface.Name)
				}
			} else {
				if ipNet.Contains(targetIP) {
					fmt.Println(targetIP, ipNet.String(), iface.Name)
				}
			}
		}
	}
	return -1, nil
}

func getActiveInterfaces() ([]net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	active := make([]net.Interface, 0)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 {
			active = append(active, iface)
		}
	}

	return active, nil
}

func filterInterfaces(interfaces []net.Interface) []net.Interface {
	filtered := make([]net.Interface, 0)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		filtered = append(filtered, iface)
	}
	return filtered
}

func parseTargetIP(target string) (net.IP, *net.IPNet, error) {
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

func isSubnetOverlap(net1, net2 *net.IPNet) bool {
	return net1.Contains(net2.IP) || net2.Contains(net1.IP)
}
