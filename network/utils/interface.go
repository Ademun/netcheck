package utils

import (
	"fmt"
	"net"
)

func FindInterfaceIdxForAddr(target string) (int, error) {
	targetIP, targetNet, err := ParseTargetAddress(target)
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
				if AreSubnetsOverlapping(targetNet, ipNet) {
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
