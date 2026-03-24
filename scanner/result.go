package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
)

type Result struct {
	IP       string
	Port     int
	Status   string
	Banner   string
	Hostname string
}

// PrintResults prints results as a sorted table
// verbosity: 0 = open only, 1 = open+closed, 2 = all
func PrintResults(results []Result, verbosity int) {
	green  := color.New(color.FgGreen).SprintfFunc()
	red    := color.New(color.FgRed).SprintfFunc()
	yellow := color.New(color.FgYellow).SprintfFunc()
	cyan   := color.New(color.FgCyan).SprintfFunc()
	grey   := color.New(color.FgWhite).SprintfFunc()

	// filter based on verbosity
	var filtered []Result
	for _, r := range results {
		switch verbosity {
		case 0:
			if r.Status == "open" {
				filtered = append(filtered, r)
			}
		case 1:
			if r.Status == "open" || r.Status == "closed" {
				filtered = append(filtered, r)
			}
		case 2:
			filtered = append(filtered, r)
		}
	}

	if len(filtered) == 0 {
		fmt.Println("\nNo results to display.")
		return
	}

	// sort by IP then port
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].IP == filtered[j].IP {
			return filtered[i].Port < filtered[j].Port
		}
		return filtered[i].IP < filtered[j].IP
	})

	// print table header
	fmt.Println()
	fmt.Printf("%-20s %-16s %-8s %-10s %s\n",
		cyan("HOST"),
		cyan("IP"),
		cyan("PORT"),
		cyan("STATUS"),
		cyan("SERVICE"),
	)
	fmt.Println("────────────────────────────────────────────────────────────────────────────")

	// print each row
	for _, r := range filtered {
		host := "-"
		if r.Hostname != "" {
			host = r.Hostname
		}

		banner := "-"
		if r.Banner != "" {
			banner = r.Banner
		}

		var statusStr string
		switch r.Status {
		case "open":
			statusStr = green("open")
		case "closed":
			statusStr = red("closed")
		case "filtered":
			statusStr = grey("filtered")
		}

		fmt.Printf("%-20s %-16s %-8s %-18s %s\n",
			host,
			r.IP,
			green(fmt.Sprintf("%d", r.Port)),
			statusStr,
			yellow(banner),
		)
	}

	// count open ports
	openCount := 0
	for _, r := range filtered {
		if r.Status == "open" {
			openCount++
		}
	}

	fmt.Println("────────────────────────────────────────────────────────────────────────────")
	fmt.Printf("Found %s open port(s) across %s host(s)\n",
		green(fmt.Sprintf("%d", openCount)),
		green(fmt.Sprintf("%d", countUniqueIPs(filtered))),
	)
}

// SaveResults saves results to a file in txt, json or csv format
func SaveResults(results []Result, filepath string) error {
	// determine format from extension
	var content string

	if strings.HasSuffix(filepath, ".json") {
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		content = string(data)

	} else if strings.HasSuffix(filepath, ".csv") {
		var sb strings.Builder
		sb.WriteString("IP,Hostname,Port,Status,Banner\n")
		for _, r := range results {
			if r.Status == "open" {
				sb.WriteString(fmt.Sprintf("%s,%s,%d,%s,%s\n",
					r.IP, r.Hostname, r.Port, r.Status, r.Banner))
			}
		}
		content = sb.String()

	} else {
		// plain text
		var sb strings.Builder
		for _, r := range results {
			if r.Status == "open" {
				sb.WriteString(fmt.Sprintf("[OPEN] %s:%d → %s\n", r.IP, r.Port, r.Banner))
			}
		}
		content = sb.String()
	}

	return os.WriteFile(filepath, []byte(content), 0644)
}

// countUniqueIPs counts distinct IPs in results
func countUniqueIPs(results []Result) int {
	seen := make(map[string]bool)
	for _, r := range results {
		seen[r.IP] = true
	}
	return len(seen)
}