package discovery

import "net"

type ARPScanner struct {
	targets []net.IP //Target host addresses
}

func NewARPScanner(targets []net.IP) *ARPScanner {
	return &ARPScanner{targets: targets}
}

func (a *ARPScanner) Discover() {
	net.Interfaces()
}
