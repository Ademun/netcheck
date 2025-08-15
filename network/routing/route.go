package routing

import (
	"fmt"
	"net"
	"runtime"
	"sort"
)

type Route struct {
	Dst     net.IP
	Mask    net.IPMask
	Gateway net.IP
	Iface   *net.Interface
	Metrics int
}

func FindRoute(dst net.IP) (*Route, error) {
	var table []Route
	switch runtime.GOOS {
	case "windows":
		t, err := getWinRoutingTable()
		if err != nil {
			return nil, err
		}
		table = t
	default:
		return nil, fmt.Errorf("OS %s not supported", runtime.GOOS)
	}

	candidates := make([]Route, 0)
	for _, route := range table {
		routeNet := net.IPNet{IP: route.Dst, Mask: route.Mask}
		if routeNet.Contains(dst) {
			candidates = append(candidates, route)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		o1, _ := candidates[i].Mask.Size()
		o2, _ := candidates[j].Mask.Size()
		return o1 > o2
	})
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Metrics < candidates[j].Metrics
	})

	return &candidates[0], nil
}
