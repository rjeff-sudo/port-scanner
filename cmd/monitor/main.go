package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"port-scanner/monitor"
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
	target    := flag.String("target", "", "IP or range (e.g. 192.168.89.1-192.168.89.254)")
	ports     := flag.String("ports", "22,80,443", "Ports to monitor")
	workers   := flag.Int("workers", 100, "Number of concurrent workers")
	timeout   := flag.Int("timeout", 1, "Connection timeout in seconds")
	interval  := flag.Int("interval", 60, "Scan interval in seconds")
	stateFile := flag.String("state", "", "File to store network state (default: auto-named)")

	flag.Parse()

	if *target == "" {
		fmt.Println("Error: -target is required")
		flag.Usage()
		os.Exit(1)
	}

	if *stateFile == "" {
		safe := strings.NewReplacer(".", "_", "/", "_", "-", "_").Replace(*target)
		*stateFile = "state_" + safe + ".json"
	}

	portList, err := parsePorts(*ports)
	if err != nil {
		fmt.Printf("Error parsing ports: %v\n", err)
		os.Exit(1)
	}

	monitor.Run(
		*target,
		portList,
		*workers,
		time.Duration(*timeout)*time.Second,
		time.Duration(*interval)*time.Second,
		*stateFile,
	)
}