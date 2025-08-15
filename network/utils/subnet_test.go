package utils

import (
	"net"
	"slices"
	"testing"
)

func TestGetHostsFromAddr(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []net.IP
		wantErr  bool
	}{
		{
			name:     "Single IPv4 address",
			input:    "192.168.1.1",
			expected: []net.IP{net.ParseIP("192.168.1.1")},
			wantErr:  false,
		},
		{
			name:     "/32 CIDR - one address",
			input:    "10.0.0.5/32",
			expected: []net.IP{net.ParseIP("10.0.0.5")},
			wantErr:  false,
		},
		{
			name:  "/30 CIDR - exclude network and broadcast",
			input: "192.168.1.0/30",
			expected: []net.IP{
				net.ParseIP("192.168.1.1"),
				net.ParseIP("192.168.1.2"),
			},
			wantErr: false,
		},
		{
			name:  "/31 CIDR - point-to-point, include both addresses",
			input: "192.168.3.0/31",
			expected: []net.IP{
				net.ParseIP("192.168.3.0"),
				net.ParseIP("192.168.3.1"),
			},
			wantErr: false,
		},
		{
			name:  "Single IPv6 address",
			input: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expected: []net.IP{
				net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
			},
			wantErr: false,
		},
		{
			name:  "Compressed IPv6 address",
			input: "2001:db8::1",
			expected: []net.IP{
				net.ParseIP("2001:db8::1"),
			},
			wantErr: false,
		},
		{
			name:  "/126 CIDR - exclude network and broadcast",
			input: "2001:db8:abcd:0012::/126",
			expected: []net.IP{
				net.ParseIP("2001:db8:abcd:0012::1"),
				net.ParseIP("2001:db8:abcd:0012::2"),
			},
			wantErr: false,
		},
		{
			name:  "/127 CIDR - point-to-point, include both addresses",
			input: "2001:db8:abcd:0013::/127",
			expected: []net.IP{
				net.ParseIP("2001:db8:abcd:0013::0"),
				net.ParseIP("2001:db8:abcd:0013::1"),
			},
			wantErr: false,
		},
		{
			name:  "/128 CIDR - single address",
			input: "2001:db8:abcd:0014::1/128",
			expected: []net.IP{
				net.ParseIP("2001:db8:abcd:0014::1"),
			},
			wantErr: false,
		},
		{
			name:     "Invalid CIDR format",
			input:    "192.168.1.0/33",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid IP address",
			input:    "256.300.1.1",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Empty input",
			input:    "",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Non-IP input",
			input:    "example.com",
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hosts, err := GetHostsFromAddr(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHostsFromAddr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if !slices.EqualFunc(hosts, tt.expected, func(ip net.IP, ip2 net.IP) bool {
				return ip.Equal(ip2)
			}) {
				t.Errorf("GetHostsFromAddr() got = %v, want %v", hosts, tt.expected)
				return
			}
		})
	}
}

func TestAreSubnetsOverlapping(t *testing.T) {
	tests := []struct {
		name     string
		net1     net.IPNet
		net2     net.IPNet
		expected bool
	}{
		{
			name:     "identical IPv4 networks",
			net1:     net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(24, 32)},
			net2:     net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(24, 32)},
			expected: true,
		},
		{
			name:     "different IPv4 networks with partial overlap (net1 contains net2 base)",
			net1:     net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(24, 32)},
			net2:     net.IPNet{IP: net.IPv4(10, 0, 0, 128), Mask: net.CIDRMask(25, 32)},
			expected: true,
		},
		{
			name:     "different IPv4 networks with partial overlap (net2 contains net1 base)",
			net1:     net.IPNet{IP: net.IPv4(192, 168, 1, 0), Mask: net.CIDRMask(25, 32)},
			net2:     net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(23, 32)},
			expected: true,
		},
		{
			name:     "non-overlapping IPv4 networks",
			net1:     net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(24, 32)},
			net2:     net.IPNet{IP: net.IPv4(10, 0, 1, 0), Mask: net.CIDRMask(24, 32)},
			expected: false,
		},
		{
			name:     "adjacent IPv4 networks (no overlap)",
			net1:     net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(25, 32)},
			net2:     net.IPNet{IP: net.IPv4(10, 0, 0, 128), Mask: net.CIDRMask(25, 32)},
			expected: false,
		},
		{
			name:     "identical IPv6 networks",
			net1:     net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(32, 128)},
			net2:     net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(32, 128)},
			expected: true,
		},
		{
			name:     "IPv6 network fully contained in another",
			net1:     net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(32, 128)},
			net2:     net.IPNet{IP: net.ParseIP("2001:db8:abcd::"), Mask: net.CIDRMask(48, 128)},
			expected: true,
		},
		{
			name:     "non-overlapping IPv6 networks",
			net1:     net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(64, 128)},
			net2:     net.IPNet{IP: net.ParseIP("2001:db9::"), Mask: net.CIDRMask(64, 128)},
			expected: false,
		},
		{
			name:     "mixed IP versions (IPv4 and IPv6)",
			net1:     net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(24, 32)},
			net2:     net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(32, 128)},
			expected: false,
		},
		{
			name:     "overlap with different subnet sizes (net1 larger)",
			net1:     net.IPNet{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(16, 32)},
			net2:     net.IPNet{IP: net.IPv4(172, 16, 1, 0), Mask: net.CIDRMask(24, 32)},
			expected: true,
		},
		{
			name:     "overlap with different subnet sizes (net2 larger)",
			net1:     net.IPNet{IP: net.IPv4(10, 1, 2, 0), Mask: net.CIDRMask(24, 32)},
			net2:     net.IPNet{IP: net.IPv4(10, 1, 0, 0), Mask: net.CIDRMask(16, 32)},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AreSubnetsOverlapping(&tt.net1, &tt.net2)
			if got != tt.expected {
				t.Errorf("AreSubnetsOverlapping() got = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBroadcastIPAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected net.IP
	}{
		{
			name:     "/24 CIDR",
			input:    "192.168.1.0/24",
			expected: net.ParseIP("192.168.1.255"),
		},
		{
			name:     "/26 CIDR",
			input:    "10.0.0.64/26",
			expected: net.ParseIP("10.0.0.127"),
		},
		{
			name:     "/23 CIDR",
			input:    "192.168.0.0/23",
			expected: net.ParseIP("192.168.1.255"),
		},
		{
			name:     "/32 CIDR",
			input:    "203.0.113.5/32",
			expected: net.ParseIP("203.0.113.5"),
		},
		{
			name:     "/0 CIDR",
			input:    "0.0.0.0/0",
			expected: net.ParseIP("255.255.255.255"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, subnet, err := net.ParseCIDR(tt.input)
			if err != nil {
				t.Errorf("Unexpected CIDR parse error %v", err)
			}

			got := BroadcastIPAddress(subnet)

			if !got.Equal(tt.expected) {
				t.Errorf("BroadcastIPAddress() got = %v, want %v", got, tt.expected)
			}
		})
	}
}
