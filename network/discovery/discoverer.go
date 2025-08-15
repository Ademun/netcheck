package discovery

import (
	"fmt"
	"net"
	"time"
)

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
