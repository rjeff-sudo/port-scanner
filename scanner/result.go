package scanner

import "fmt"

type Result struct {
	IP     string
	Port   int
	Status string
	Banner string // new
}

func PrintResults(results []Result) {
	fmt.Println("\n--- Scan Results ---")
	found := false

	for _, r := range results {
		if r.Status == "open" {
			if r.Banner != "" {
				fmt.Printf("[OPEN] %s:%d → %s\n", r.IP, r.Port, r.Banner)
			} else {
				fmt.Printf("[OPEN] %s:%d\n", r.IP, r.Port)
			}
			found = true
		}
	}

	if !found {
		fmt.Println("No open ports found.")
	}
}