package discovery

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"time"
)

const (
	maxProcs       = 10
	defaultDstPort = 80
	defaultSrcPort = 443
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

func sortResults(hosts []*Host) {
	sort.Slice(hosts, func(i, j int) bool {
		return bytes.Compare(hosts[i].IP, hosts[j].IP) < 0
	})
}
