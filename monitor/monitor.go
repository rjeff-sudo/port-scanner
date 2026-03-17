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
}

// Compare takes two snapshots and returns what changed between them
func Compare(baseline, current Snapshot) []Change {
	var changes []Change

	for ip, ports := range current.Devices {
		baselinePorts, existed := baseline.Devices[ip]

		if !existed {
			for _, port := range ports {
				changes = append(changes, Change{
					Type: "new_device",
					IP:   ip,
					Port: port,
				})
			}
			continue
		}

		baselinePortSet := toSet(baselinePorts)
		for _, port := range ports {
			if !baselinePortSet[port] {
				changes = append(changes, Change{
					Type: "new_port",
					IP:   ip,
					Port: port,
				})
			}
		}
	}

	for ip, baselinePorts := range baseline.Devices {
		currentPorts, stillExists := current.Devices[ip]

		if !stillExists {
			for _, port := range baselinePorts {
				changes = append(changes, Change{
					Type: "lost_device",
					IP:   ip,
					Port: port,
				})
			}
			continue
		}

		currentPortSet := toSet(currentPorts)
		for _, port := range baselinePorts {
			if !currentPortSet[port] {
				changes = append(changes, Change{
					Type: "closed_port",
					IP:   ip,
					Port: port,
				})
			}
		}
	}

	return changes
}

// PrintChanges displays detected changes with clear labels
func PrintChanges(changes []Change) {
	for _, c := range changes {
		switch c.Type {
		case "new_device":
			fmt.Printf("  [NEW DEVICE]   %s:%d\n", c.IP, c.Port)
		case "lost_device":
			fmt.Printf("  [LOST DEVICE]  %s:%d\n", c.IP, c.Port)
		case "new_port":
			fmt.Printf("  [NEW PORT]     %s:%d just opened\n", c.IP, c.Port)
		case "closed_port":
			fmt.Printf("  [PORT CLOSED]  %s:%d just closed\n", c.IP, c.Port)
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

// toSet converts a slice of ints into a map for O(1) lookup
func toSet(ports []int) map[int]bool {
	set := make(map[int]bool)
	for _, p := range ports {
		set[p] = true
	}
	return set
}