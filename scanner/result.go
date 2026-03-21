package scanner

import (
	"fmt"
	"sort"

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
	green  := color.New(color.FgGreen).SprintfFunc()
	yellow := color.New(color.FgYellow).SprintfFunc()
	cyan   := color.New(color.FgCyan).SprintfFunc()

	// collect open results only
	var open []Result
	for _, r := range results {
		if r.Status == "open" {
			open = append(open, r)
		}
	}

	if len(open) == 0 {
		fmt.Println("\nNo open ports found.")
		return
	}

	// sort by IP then port
	sort.Slice(open, func(i, j int) bool {
		if open[i].IP == open[j].IP {
			return open[i].Port < open[j].Port
		}
		return open[i].IP < open[j].IP
	})

	// print table header
	fmt.Println()
	fmt.Printf("%-20s %-16s %-8s %s\n",
		cyan("HOST"),
		cyan("IP"),
		cyan("PORT"),
		cyan("SERVICE"),
	)
	fmt.Println("─────────────────────────────────────────────────────────────────────")

	// print each row
	for _, r := range open {
		host := "-"
		if r.Hostname != "" {
			host = r.Hostname
		}

		banner := "-"
		if r.Banner != "" {
			banner = r.Banner
		}

		fmt.Printf("%-20s %-16s %s      %s\n",
			host,
			r.IP,
			green(fmt.Sprintf("%-4d", r.Port)),
			yellow(banner),
		)
	}

	// print summary footer
	fmt.Println("─────────────────────────────────────────────────────────────────────")
	fmt.Printf("Found %s open port(s) across %s host(s)\n",
		green(fmt.Sprintf("%d", len(open))),
		green(fmt.Sprintf("%d", countUniqueIPs(open))),
	)
}

// countUniqueIPs counts distinct IPs in results
func countUniqueIPs(results []Result) int {
	seen := make(map[string]bool)
	for _, r := range results {
		seen[r.IP] = true
	}
	return len(seen)
}