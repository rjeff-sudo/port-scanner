package scanner

import "fmt"

// Result holds the outcome of scanning a single IP:port combination
type Result struct {
	IP     string
	Port   int
	Status string // "open", "closed", "filtered"
}

// PrintResults prints only the open ports to the terminal
func PrintResults(results []Result) {
	fmt.Println("\n--- Scan Results ---")
	found := false

	for _, r := range results {
		if r.Status == "open" {
			fmt.Printf("[OPEN] %s:%d\n", r.IP, r.Port)
			found = true
		}
	}

	if !found {
		fmt.Println("No open ports found.")
	}
}