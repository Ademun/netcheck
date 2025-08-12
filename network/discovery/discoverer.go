package discovery

import (
	"net"
	"time"
)

// Host represents a discovered network host with its IP and MAC address
type Host struct {
	IP    net.IP
	MAC   net.HardwareAddr
	Delay time.Duration
}

type Discoverer interface {
	Discover() ([]Host, error)
}
