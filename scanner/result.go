package scanner

import (
	"fmt"

	"github.com/fatih/color"
)

type Result struct {
	IP       string
	Port     int
	Status   string
	Banner   string
	Hostname string
}

func PrintResults(results []Result) {
	fmt.Println("\n--- Scan Results ---")
	found := false

	green  := color.New(color.FgGreen).SprintfFunc()
	yellow := color.New(color.FgYellow).SprintfFunc()

	for _, r := range results {
		if r.Status == "open" {
			host := r.IP
			if r.Hostname != "" {
				host = fmt.Sprintf("%s (%s)", r.IP, r.Hostname)
			}
			if r.Banner != "" {
				fmt.Printf("%s %s:%d → %s\n",
					green("[OPEN]"),
					host,
					r.Port,
					yellow(r.Banner),
				)
			} else {
				fmt.Printf("%s %s:%d\n",
					green("[OPEN]"),
					host,
					r.Port,
				)
			}
			found = true
		}
	}

	if !found {
		fmt.Println("No open ports found.")
	}
}