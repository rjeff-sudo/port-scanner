package monitor

import (
	"fmt"
	"time"

	"port-scanner/scanner"
)

// Change represents a single detected change on the network
type Change struct {
	Type   string
	IP     string
	Port   int
	Banner string
}

// Compare takes two snapshots and returns what changed between them
func Compare(baseline, current Snapshot) []Change {
	var changes []Change

	// Check for new devices and new ports on existing devices
	for ip, ports := range current.Devices {
		baselinePorts, existed := baseline.Devices[ip]

		if !existed {
			// Entire device is new
			for port, banner := range ports {
				changes = append(changes, Change{
					Type:   "new_device",
					IP:     ip,
					Port:   port,
					Banner: banner,
				})
			}
			continue
		}

		// Device existed — check for new ports
		for port, banner := range ports {
			if _, wasOpen := baselinePorts[port]; !wasOpen {
				changes = append(changes, Change{
					Type:   "new_port",
					IP:     ip,
					Port:   port,
					Banner: banner,
				})
			}
		}
	}

	// Check for lost devices and closed ports
	for ip, baselinePorts := range baseline.Devices {
		currentPorts, stillExists := current.Devices[ip]

		if !stillExists {
			// Entire device disappeared
			for port, banner := range baselinePorts {
				changes = append(changes, Change{
					Type:   "lost_device",
					IP:     ip,
					Port:   port,
					Banner: banner,
				})
			}
			continue
		}

		// Device still exists — check for closed ports
		for port, banner := range baselinePorts {
			if _, stillOpen := currentPorts[port]; !stillOpen {
				changes = append(changes, Change{
					Type:   "closed_port",
					IP:     ip,
					Port:   port,
					Banner: banner,
				})
			}
		}
	}

	return changes
}

// PrintChanges displays detected changes with clear labels
func PrintChanges(changes []Change) {
	for _, c := range changes {
		banner := ""
		if c.Banner != "" {
			banner = " -> " + c.Banner
		}

		switch c.Type {
		case "new_device":
			fmt.Printf("  [NEW DEVICE]   %s:%d%s\n", c.IP, c.Port, banner)
		case "lost_device":
			fmt.Printf("  [LOST DEVICE]  %s:%d%s\n", c.IP, c.Port, banner)
		case "new_port":
			fmt.Printf("  [NEW PORT]     %s:%d%s just opened\n", c.IP, c.Port, banner)
		case "closed_port":
			fmt.Printf("  [PORT CLOSED]  %s:%d%s just closed\n", c.IP, c.Port, banner)
		}
	}
}

// Run starts the monitoring loop
func Run(target string, ports []int, workers int, timeout time.Duration, interval time.Duration, stateFile string) {
	fmt.Printf("\n--- Network Monitor Started ---\n")
	fmt.Printf("Target: %s | Interval: %v\n\n", target, interval)

	ips, err := scanner.ParseIPs(target)
	if err != nil {
		fmt.Printf("Error parsing target: %v\n", err)
		return
	}

	baseline, err := LoadSnapshot(stateFile)
	if err != nil {
		fmt.Println("[*] No previous state found. Establishing baseline...")
		results := scanner.RunWorkerPool(ips, ports, workers, timeout)
		baseline = NewSnapshot(results)
		SaveSnapshot(baseline, stateFile)
		fmt.Printf("[+] Baseline established — %d device(s) found\n\n", len(baseline.Devices))
	} else {
		fmt.Printf("[+] Loaded previous state from %s\n\n", stateFile)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		<-ticker.C

		fmt.Printf("[%s] Scanning...\n", time.Now().Format("15:04:05"))

		results := scanner.RunWorkerPool(ips, ports, workers, timeout)
		current := NewSnapshot(results)
		changes := Compare(baseline, current)

		if len(changes) == 0 {
			fmt.Printf("[%s] No changes detected\n\n", time.Now().Format("15:04:05"))
		} else {
			fmt.Printf("[%s] %d change(s) detected:\n", time.Now().Format("15:04:05"), len(changes))
			PrintChanges(changes)
			fmt.Println()
		}

		baseline = current
		SaveSnapshot(baseline, stateFile)
	}
}