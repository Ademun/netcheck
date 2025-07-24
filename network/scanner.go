package network

type Scanner interface {
	ScanHost(string, []string) []Result
}

// Possible port states
type PortStatus int

const (
	OPEN     PortStatus = iota //Available and accepting connections
	FILTERED                   //Filtered by firewall (no response)
	CLOSED                     //Available but not accepting connections
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

func (p PortStatus) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

// Port scan result
type Result struct {
	Port    string
	Status  PortStatus
	Banners string
}
