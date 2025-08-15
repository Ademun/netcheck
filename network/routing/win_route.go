package routing

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	iphlpapiDLL             = "iphlpapi.dll"
	procGetTable            = "GetIpForwardTable"
	errorInsufficientBuffer = 122
)

// mibIPForwardRow matches Windows' _MIB_IPFORWARDROW structure
// https://learn.microsoft.com/en-us/windows/win32/api/ipmib/ns-ipmib-mib_ipforwardrow
type mibIPForwardRow struct {
	dwForwardDest      uint32 // Destination IP address
	dwForwardMask      uint32 // Subnet mask
	dwForwardPolicy    uint32 // Forwarding policy (unused, set to 0)
	dwForwardNextHop   uint32 // Next hop IP address
	dwForwardIfIndex   uint32 // Interface index
	dwForwardType      uint32 // Route type (e.g., MIB_IPROUTE_TYPE_DIRECT)
	dwForwardProto     uint32 // Routing protocol (e.g., MIB_IPPROTO_NETMGMT)
	dwForwardAge       uint32 // Route age in seconds
	dwForwardNextHopAS uint32 // Next hop Autonomous System number
	dwForwardMetric1   uint32 // Primary routing metric
	dwForwardMetric2   uint32 // Secondary metric
	dwForwardMetric3   uint32 // Additional metric
	dwForwardMetric4   uint32 // Additional metric
	dwForwardMetric5   uint32 // Additional metric
}

// mibIPForwardTable matches Windows' _MIB_IPFORWARDTABLE structure
// https://learn.microsoft.com/en-us/windows/win32/api/ipmib/ns-ipmib-mib_ipforwardtable
type mibIPForwardTable struct {
	numEntries uint32             // Number of entries in table
	table      [1]mibIPForwardRow // Variable-length array placeholder
}

func getWinRoutingTable() ([]Route, error) {
	if !(runtime.GOOS == "windows") {
		return nil, fmt.Errorf("is only supported on Windows")
	}

	mod := syscall.NewLazyDLL(iphlpapiDLL)
	proc := mod.NewProc(procGetTable)

	var size uint32
	r0, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if r0 != errorInsufficientBuffer {
		return nil, fmt.Errorf("dll first call error: %v", syscall.Errno(r0))
	}

	buf := make([]byte, size)
	table := (*mibIPForwardTable)(unsafe.Pointer(&buf[0]))
	r0, _, _ = proc.Call(uintptr(unsafe.Pointer(table)), uintptr(unsafe.Pointer(&size)), 1)
	if r0 != 0 {
		return nil, fmt.Errorf("dll second call error: %v", syscall.Errno(r0))
	}

	rows := unsafe.Slice(&table.table[0], table.numEntries)

	routes := make([]Route, len(rows))
	for i, row := range rows {
		iface, err := net.InterfaceByIndex(int(row.dwForwardIfIndex))
		if err != nil {
			return nil, fmt.Errorf("interface lookup error: %v", err)
		}

		routes[i] = Route{
			Dst:     dwordToIp(row.dwForwardDest),
			Mask:    net.IPMask(dwordToIp(row.dwForwardMask)),
			Gateway: dwordToIp(row.dwForwardNextHop),
			Iface:   iface,
			Metrics: int(row.dwForwardMetric1),
		}
	}
	return routes, nil
}

func dwordToIp(dword uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, dword)
	return ip
}
