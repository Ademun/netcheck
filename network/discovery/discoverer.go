package discovery

import "net"

// Host represents a discovered network host with its IP and MAC address
type Host struct {
	IP  net.IP
	MAC net.HardwareAddr
}

type Dicoverer interface {
	Discover() ([]Host, error)
}
