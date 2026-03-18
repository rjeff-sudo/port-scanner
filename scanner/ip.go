package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// ParseIPs takes a string input and returns a slice of IP strings
// Accepts either a single IP or a range like "192.168.1.1-192.168.1.10"
func ParseIPs(input string) ([]string, error) {
	// Check if it's a range
	if strings.Contains(input, "-") {
		parts := strings.Split(input, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid range format: %s", input)
		}
		return generateIPRange(parts[0], parts[1])
	}

	// Otherwise treat as single IP
	if net.ParseIP(input) == nil {
		return nil, fmt.Errorf("invalid IP address: %s", input)
	}
	return []string{input}, nil
}

// generateIPRange returns all IPs between startIP and endIP inclusive
func generateIPRange(startIP, endIP string) ([]string, error) {
	start := net.ParseIP(startIP).To4()
	end := net.ParseIP(endIP).To4()

	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid IP in range: %s - %s", startIP, endIP)
	}

	startInt := binary.BigEndian.Uint32(start)
	endInt := binary.BigEndian.Uint32(end)

	if startInt > endInt {
		return nil, fmt.Errorf("start IP must be less than or equal to end IP")
	}

	var ips []string
	for i := startInt; i <= endInt; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// LookupHostname does a reverse DNS lookup on an IP
// Returns the hostname or empty string if none found
func LookupHostname(ip string) string {
	hostnames, err := net.LookupAddr(ip)
	if err != nil || len(hostnames) == 0 {
		return ""
	}
	// LookupAddr returns FQDNs with trailing dot — trim it
	return strings.TrimSuffix(hostnames[0], ".")
}