package cmd

import "github.com/ademun/netcheck/network"

func ColorizePortStatus(status network.PortStatus) string {
	switch status {
	case network.OPEN:
		return "\033[32mopen\033[0m"
	case network.FILTERED:
		return "\033[33mfiltered\033[0m"
	case network.CLOSED:
		return "\033[90mclosed\033[0m"
	default:
		return "unknown"
	}
}
