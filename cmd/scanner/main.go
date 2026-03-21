package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"port-scanner/scanner"
)

func parsePorts(input string) ([]int, error) {
	var ports []int

	if strings.Contains(input, "-") {
		parts := strings.Split(input, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port range: %s", input)
		}
		start, err1 := strconv.Atoi(parts[0])
		end, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("invalid port numbers in range: %s", input)
		}
		if start < 1 || end > 65535 || start > end {
			return nil, fmt.Errorf("port range must be between 1-65535")
		}
		for i := start; i <= end; i++ {
			ports = append(ports, i)
		}
		return ports, nil
	}

	for _, p := range strings.Split(input, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port: %s", p)
		}
		ports = append(ports, port)
	}

	return ports, nil
}

func main() {
	target  := flag.String("target", "", "IP or range (e.g. 192.168.89.1-192.168.89.254)")
	ports   := flag.String("ports", "1-1024", "Ports to scan (e.g. 1-1024 or 80,443,8080)")
	workers := flag.Int("workers", 100, "Number of concurrent workers")
	timeout := flag.Int("timeout", 1, "Connection timeout in seconds")

	flag.Parse()

	if *target == "" {
		fmt.Println("Error: -target is required")
		flag.Usage()
		os.Exit(1)
	}

	ips, err := scanner.ParseIPs(*target)
	if err != nil {
		fmt.Printf("Error parsing target: %v\n", err)
		os.Exit(1)
	}

	portList, err := parsePorts(*ports)
	if err != nil {
		fmt.Printf("Error parsing ports: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nScanning %d IP(s) across %d port(s) with %d workers...\n",
		len(ips), len(portList), *workers)

	results := scanner.RunWorkerPool(ips, portList, *workers, time.Duration(*timeout)*time.Second)
	scanner.PrintResults(results)

	fmt.Printf("\nScan complete. %d total probes.\n", len(results))
}