package discovery

import (
	"fmt"
	"net"

	"github.com/ademun/netcheck/network/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ARPScanner struct {
	target string //Target subnetwork
}

func NewARPScanner(target string) *ARPScanner {
	return &ARPScanner{target: target}
}

func (a *ARPScanner) Discover() error {
	iface, err := utils.InterfaceForAddr(a.target)
	if err != nil {
		fmt.Println(err)
		return err
	}
	if iface == nil {
		return fmt.Errorf("no suitable interface found")
	}

	fmt.Println(iface.Description)

	ifaceIp, _, err := utils.InterfaceIPv4Net(iface)
	if err != nil {
		return err
	}
	hosts, err := utils.HostsFromSubnet(a.target)
	if err != nil {
		return err
	}
	sock, err := utils.PcapSocket(iface.Name)
	if err != nil {
		return err
	}

	mac, err := utils.IfaceHardwareAddr(iface.Name)
	if err != nil {
		fmt.Println(err)
		return err
	}

	for _, host := range hosts {
		packet, err := arpPacket(mac, ifaceIp, host)
		if err != nil {
			return err
		}
		err = sock.WritePacketData(packet)
		if err != nil {
			fmt.Println(err)
			return err
		}
	}
	return err
}

func arpPacket(ifaceMac net.HardwareAddr, ifaceIpv4, targetIpv4 net.IP) ([]byte, error) {
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       ifaceMac,
		DstMAC:       []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		EthernetType: layers.EthernetTypeARP,
	}
	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   ifaceMac,
		SourceProtAddress: ifaceIpv4.To4(),
		DstHwAddress:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    targetIpv4.To4(),
	}

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, options, ethernetLayer, arpLayer)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return buf.Bytes(), nil
}

/*
frame := make([]byte, 28)
	//ARP
	//Hardware type (2 bytes) - Ethernet (0x0001)
	binary.BigEndian.PutUint16(frame[0:2], 0x0001)
	//Protocol type (2 bytes) - IPv4 (0x0800)
	binary.BigEndian.PutUint16(frame[2:4], 0x0800)
	//Hardware address length (1 byte)
	frame[4] = 6 //MAC (6 bytes)
	//Protocol length (1 byte)
	frame[5] = 4 //IPv4 (4 bytes)
	//Opertaion (2 бytes) - ARP Request (0x0001)
	binary.BigEndian.PutUint16(frame[6:8], 0x0001)
	//Sender MAC (6 bytes)
	copy(frame[8:14], ifaceMac)
	//Sender Protocol Address (4 bytes)
	copy(frame[14:18], ifaceIpv4)
	//Target Hardware Address (6 байт) - unknown
	copy(frame[18:24], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	//Target Protocol Address (4 байта) - искомый IP
	copy(frame[24:28], targetIpv4)*/
