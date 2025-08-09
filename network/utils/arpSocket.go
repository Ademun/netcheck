package utils

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/windows"
)

func CreateWindowsSocket(ip [4]byte) (int, error) {
	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		fmt.Println(err)
		return -1, err
	}

	addr := windows.SockaddrInet4{
		Port: 0,
		Addr: ip,
	}

	err = windows.Bind(fd, &addr)
	if err != nil {
		fmt.Println("bind", err)
		return -1, err
	}

	const (
		SIO_RCVALL = windows.IOC_IN | windows.IOC_VENDOR | 1
		RCVALL_ON  = 1
	)
	var inBuf [4]byte
	binary.LittleEndian.PutUint32(inBuf[:], RCVALL_ON)
	var bytesReturned uint32
	err = windows.WSAIoctl(fd, SIO_RCVALL, &inBuf[0], uint32(len(inBuf)), nil, 0, &bytesReturned, nil, 0)
	if err != nil {
		fmt.Println("ioctl", err)
		windows.Close(fd)
		return -1, err
	}

	fmt.Println(fd, int(fd))
	return int(fd), nil
}
