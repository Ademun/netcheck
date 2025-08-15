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

func FindRoute(dst net.IP, routes []Route) *Route {
	candidates := make([]Route, 0)
	for _, route := range routes {
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

	return &candidates[0]
}

func GetRoutingTable() ([]Route, error) {
	switch runtime.GOOS {
	case "windows":
		t, err := getWinRoutingTable()
		if err != nil {
			return nil, err
		}
		return t, nil
	default:
		return nil, fmt.Errorf("OS %s not supported", runtime.GOOS)
	}
}
