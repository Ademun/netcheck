package discovery

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/ademun/netcheck/network/utils"
	"golang.org/x/sys/windows"
)

type ARPScanner struct {
	target string //Target subnetwork
}

func NewARPScanner(target string) *ARPScanner {
	tocken := windows.GetCurrentProcessToken()
	if !tocken.IsElevated() {
		fmt.Println("elevated priviledges required to run arp scanning")
		return nil
	}
	return &ARPScanner{target: target}
}

func (a *ARPScanner) Discover() error {
	idx, err := utils.FindInterfaceIdxForAddr(a.target)
	if err != nil {
		fmt.Println(err)
		return err
	}
	if idx == -1 {
		fmt.Println("no iface found")
		return fmt.Errorf("no suitable interface found")
	}

	iface, _ := net.InterfaceByIndex(idx)
	ifaceIp, err := utils.GetInterfaceIPv4Addr(iface)
	if err != nil {
		return err
	}
	fmt.Println(ifaceIp.String())
	hosts, err := utils.GetHostsFromSubnet(a.target)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fd, err := utils.CreateWindowsSocket([4]byte(ifaceIp))
	if err != nil {
		fmt.Println(err)
		return err
	}

	dstAddr := windows.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{255, 255, 255, 255},
	}

	for _, host := range hosts {
		packet := arpPacket(iface.HardwareAddr, ifaceIp, host)
		err := windows.Sendto(windows.Handle(fd), packet, 0, &dstAddr)
		fmt.Printf("sent %d bytes to %s", len(packet), host.String())
		if err != nil {
			fmt.Println(err)
			return err
		}
	}
	return err
}

func arpPacket(ifaceMac net.HardwareAddr, ifaceIpv4, targetIpv4 net.IP) []byte {
	frame := make([]byte, 42)

	//Ethernet
	//Destination MAC (6 bytes) - broadcast
	copy(frame[0:6], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	//Src MAC (6 bytes)
	copy(frame[6:12], ifaceMac)
	//Packet type (2 bytes) - ARP (0x0806)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)

	//ARP
	//Hardware type (2 bytes) - Ethernet (0x0001)
	binary.BigEndian.PutUint16(frame[14:16], 0x0001)
	//Protocol type (2 bytes) - IPv4 (0x0800)
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	//Hardware address length (1 byte)
	frame[18] = 6 //MAC (6 bytes)
	//Protocol length (1 byte)
	frame[19] = 4 //IPv4 (4 bytes)
	//Opertaion (2 бytes) - ARP Request (0x0001)
	binary.BigEndian.PutUint16(frame[20:22], 0x0001)
	//Sender MAC (6 bytes)
	copy(frame[22:28], ifaceMac)
	//Sender Protocol Address (4 bytes)
	copy(frame[28:32], ifaceIpv4)
	//Target Hardware Address (6 байт) - unknown
	copy(frame[32:38], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	//Target Protocol Address (4 байта) - искомый IP
	copy(frame[38:42], targetIpv4)

	return frame
}
