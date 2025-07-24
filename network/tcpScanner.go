package network

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

type TCPScanner struct{}

func (s *TCPScanner) ScanHost(target string, ports []string) []Result {

	results := make([]Result, 0, len(ports))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	semaphore := make(chan struct{}, 500)
	out := make(chan Result)
	wg := &sync.WaitGroup{}

	wg.Add(len(ports))
	for _, p := range ports {
		go func(port string) {
			defer wg.Done()
			semaphore <- struct{}{}
			s.scanPort(ctx, out, "tcp", target, port)
			<-semaphore
		}(p)
	}
	go func() {
		wg.Wait()
		close(out)
	}()

	for r := range out {
		results = append(results, r)
	}
	return results
}

func (s *TCPScanner) scanPort(ctx context.Context, out chan Result, protocol string, target string, port string) {
	address := net.JoinHostPort(target, port)
	conn, err := net.DialTimeout(protocol, address, time.Second*5)
	select {
	case <-ctx.Done():
		return
	default:
		if err != nil {
			if isConnectionRefused(err) {
				out <- Result{Port: port, Status: CLOSED}
				return
			}
			out <- Result{Port: port, Status: FILTERED}
			return
		}
	}
	defer conn.Close()
	service := DetectService(conn, port)
	select {
	case <-ctx.Done():
		return
	case out <- Result{Port: port, Status: OPEN, Banners: service.Name}:
	}
}

func isConnectionRefused(err error) bool {
	return strings.Contains(err.Error(), "connectex")
}
