package utils

import (
	"fmt"
	"net"
	"slices"

	"github.com/google/gopacket/pcap"
)

func InterfaceForAddr(target string) (*pcap.Interface, error) {
	targetIP, targetNet, err := ParseTargetAddress(target)
	if err != nil {
		return nil, err
	}
	ifaces, err := ActiveInterfaces()
	if err != nil {
		return nil, err
	}
	ifaces = filterInterfaces(ifaces)

	for _, iface := range ifaces {
		for _, addr := range iface.Addresses {
			ipNet := &net.IPNet{
				IP:   addr.IP,
				Mask: addr.Netmask,
			}
			if targetNet != nil {
				if AreSubnetsOverlapping(targetNet, ipNet) {
					return &iface, nil
				}
			} else {
				if ipNet.Contains(targetIP) {
					return &iface, nil
				}
			}
		}
	}
	return nil, nil
}

func ActiveInterfaces() ([]pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("PCAP device error:", err)
	}
	active := make([]pcap.Interface, 0)
	for _, device := range devices {
		if device.Flags&0x2 != 0 {
			active = append(active, device)
		}
	}

	return active, nil
}

func InterfaceIPv4Net(iface *pcap.Interface) (net.IP, net.IPMask, error) {
	for _, addr := range iface.Addresses {
		ipNet := net.IPNet{
			IP:   addr.IP,
			Mask: addr.Netmask,
		}
		if ip := ipNet.IP.To4(); ip != nil {
			return ip, ipNet.Mask, nil
		}
	}
	return nil, nil, fmt.Errorf("interface %s doesn't have an ipv4 address", iface.Name)
}

func filterInterfaces(interfaces []pcap.Interface) []pcap.Interface {
	filtered := make([]pcap.Interface, 0)
	for _, iface := range interfaces {
		if iface.Flags&0x1 != 0 && len(iface.Addresses) > 0 {
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

func IfaceHardwareAddr(pcapName string) (net.HardwareAddr, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("PCAP device error: %s", err)
	}

	idx := slices.IndexFunc(devices, func(device pcap.Interface) bool { return device.Name == pcapName })
	if idx == -1 {
		return nil, fmt.Errorf("device %s not found", pcapName)
	}
	device := devices[idx]

	sysIfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("system interface error: %s", err)
	}

	sysInfo := make(map[string]sysIfaceInfo)
	for _, iface := range sysIfaces {
		ips := make([]net.IP, 0)
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok {
				ips = append(ips, ipNet.IP)
			}
		}
		sysInfo[iface.Name] = sysIfaceInfo{ips: ips, mac: iface.HardwareAddr}
	}

	if info, exists := sysInfo[device.Name]; exists {
		return info.mac, nil
	}

	deviceIps := make([]net.IP, 0, len(device.Addresses))
	for _, addr := range device.Addresses {
		deviceIps = append(deviceIps, addr.IP)
	}

	for _, info := range sysInfo {
		if ipSetEqual(deviceIps, info.ips) {
			return info.mac, nil
		}
	}
	return nil, fmt.Errorf("no system interface matches device %s", pcapName)
}

func ipSetEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}

	for _, ipA := range a {
		found := false
		for _, ipB := range b {
			if ipA.Equal(ipB) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
