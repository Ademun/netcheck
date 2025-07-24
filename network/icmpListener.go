package network

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type ICMPListener struct {
	conn    *icmp.PacketConn
	packets chan ICMPResponse
	done    chan struct{}
}

type ICMPResponse struct {
	SourceIP  net.IP
	DestPort  int
	ErrorType icmp.Type
	ErrorCode int
}

func NewICMPListener() (*ICMPListener, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	return &ICMPListener{
		conn:    conn,
		packets: make(chan ICMPResponse),
		done:    make(chan struct{}),
	}, nil
}

func (l *ICMPListener) Start() {
	go l.listen()
}

func (l *ICMPListener) Stop() {
	close(l.done)
	l.conn.Close()
}

func (l *ICMPListener) listen() {
	buf := make([]byte, 1024)
	for {
		select {
		case <-l.done:
			return
		default:
			l.conn.SetReadDeadline(time.Now().Add(5 * time.Second))

			n, peer, err := l.conn.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}

			msg, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), buf[:n])
			if err != nil {
				continue
			}
			fmt.Println("Read msg:", msg)

			if msg.Type != ipv4.ICMPTypeDestinationUnreachable {
				continue
			}

			body, ok := msg.Body.(*icmp.DstUnreach)
			if !ok || len(body.Data) < 20 {
				continue
			}

			ipHeader, err := ipv4.ParseHeader(body.Data)
			fmt.Println("Parsed ip header:", ipHeader)
			if err != nil || ipHeader.Protocol != 17 {

			}

			if len(body.Data) < ipHeader.Len+8 {
				continue
			}

			udpData := body.Data[ipHeader.Len:]
			dstPort := int(udpData[2])<<8 | int(udpData[3])

			l.packets <- ICMPResponse{
				SourceIP:  net.ParseIP(peer.String()),
				DestPort:  dstPort,
				ErrorType: msg.Type,
				ErrorCode: msg.Code,
			}
		}
	}
}
