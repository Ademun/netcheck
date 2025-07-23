package network

import (
	"strconv"
	"strings"
)

// Processes strings like 80,90-100 or -100, 200-300
func SplitPorts(ports string) []string {
	result := make([]string, 0)
	ranges := strings.SplitSeq(ports, ",")
	for r := range ranges {
		if strings.Contains(r, "-") {
			result = append(result, portsFromRange(r)...)
		}
		if p := ConvPort(r); p != -1 {
			result = append(result, r)
		}
	}
	return result
}

func portsFromRange(ran string) []string {
	result := make([]string, 0)
	borders := strings.Split(ran, "-")
	//If input is like 10-20-30, it only makes sense to iterate from 10 to 30
	start, end := borders[0], borders[len(borders)-1]

	//For example -443 is identical to 0-443, 443- is identical to 443-65353, also handles invalid inputs in a way
	iStart := ConvPort(start)
	if iStart == -1 {
		iStart = 0
	}
	iEnd := ConvPort(end)
	if iEnd == -1 {
		iEnd = 65353
	}
	if iStart > iEnd {
		t := iStart
		iStart = iEnd
		iEnd = t
	}

	for i := iStart; i <= iEnd; i++ {
		result = append(result, strconv.Itoa(i))
	}
	return result
}

func ConvPort(port string) int {
	v, err := strconv.ParseInt(port, 10, 32)
	if err != nil {
		return -1
	}
	return int(v)
}
