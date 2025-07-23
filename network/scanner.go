package network

import (
	"context"
	"net"
	"sync"
	"time"
)

type PortStatus int

const (
	OPEN PortStatus = iota
	FILTERED
	CLOSED
)

func (p PortStatus) String() string {
	switch p {
	case OPEN:
		return "open"
	case FILTERED:
		return "filtered"
	case CLOSED:
		return "closed"
	}
	return "unknown"
}

type Result struct {
	Port   string
	Status PortStatus
}

func ScanHost(target string, ports []string) []Result {
	results := make([]Result, 0, len(ports))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	semaphore := make(chan struct{}, 100)
	out := make(chan Result)
	wg := &sync.WaitGroup{}

	wg.Add(len(ports))
	for _, p := range ports {
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			scanConn(ctx, out, "tcp", target, p)
			<-semaphore
		}()
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

func scanConn(ctx context.Context, out chan Result, protocol string, target string, port string) {
	address := net.JoinHostPort(target, port)
	_, err := net.DialTimeout(protocol, address, time.Second*10)
	select {
	case <-ctx.Done():
		return
	default:
		if err != nil {
			out <- Result{Port: port, Status: CLOSED}
			return
		}
		out <- Result{Port: port, Status: OPEN}
	}
}
