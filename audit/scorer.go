package audit

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ScannerResult mirrors scanner.Result to avoid circular imports
type ScannerResult struct {
	IP       string
	Port     int
	Status   string
	Banner   string
	Hostname string
	OS       string
}

// ScanReport holds the full audit result for a network
type ScanReport struct {
	Target     string
	ScannedAt  time.Time
	Score      int
	RiskLabel  string
	Total      int
	Critical   []Finding
	High       []Finding
	Medium     []Finding
	Low        []Finding
	Info       []Finding
	AllDevices []DeviceSummary
}

// DeviceSummary holds per-device risk overview
type DeviceSummary struct {
	IP       string
	Hostname string
	OS       string
	Ports    []int
	Risk     string
}

// AuditResults takes scanner results and returns a full ScanReport
func AuditResults(target string, results []ScannerResult) ScanReport {
	report := ScanReport{
		Target:    target,
		ScannedAt: time.Now(),
	}

	deviceMap := make(map[string]*DeviceSummary)

	for _, r := range results {
		if r.Status != "open" || r.Banner == "" || r.Banner == "-" {
			continue
		}

		if _, exists := deviceMap[r.IP]; !exists {
			deviceMap[r.IP] = &DeviceSummary{
				IP:       r.IP,
				Hostname: r.Hostname,
				OS:       r.OS,
				Risk:     "INFO",
			}
		}
		deviceMap[r.IP].Ports = append(deviceMap[r.IP].Ports, r.Port)

		finding := CheckBanner(r.IP, r.Port, r.Banner)

		deviceMap[r.IP].Risk = higherRisk(deviceMap[r.IP].Risk, finding.Risk)

		switch finding.Risk {
		case "CRITICAL":
			report.Critical = append(report.Critical, finding)
		case "HIGH":
			report.High = append(report.High, finding)
		case "MEDIUM":
			report.Medium = append(report.Medium, finding)
		case "LOW":
			report.Low = append(report.Low, finding)
		default:
			report.Info = append(report.Info, finding)
		}

		report.Total++
	}

	for _, d := range deviceMap {
		report.AllDevices = append(report.AllDevices, *d)
	}
	sort.Slice(report.AllDevices, func(i, j int) bool {
		return report.AllDevices[i].IP < report.AllDevices[j].IP
	})

	report.Score = calculateScore(report)
	report.RiskLabel = scoreLabel(report.Score)

	return report
}

func calculateScore(r ScanReport) int {
	score := 100
	score -= len(r.Critical) * 20
	score -= len(r.High) * 10
	score -= len(r.Medium) * 5
	score -= len(r.Low) * 2

	if score < 0 {
		score = 0
	}
	return score
}

func scoreLabel(score int) string {
	switch {
	case score >= 80:
		return "LOW RISK"
	case score >= 60:
		return "MODERATE RISK"
	case score >= 40:
		return "HIGH RISK"
	default:
		return "CRITICAL RISK"
	}
}

func higherRisk(a, b string) string {
	order := map[string]int{
		"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
	}
	if order[strings.ToUpper(b)] > order[strings.ToUpper(a)] {
		return strings.ToUpper(b)
	}
	return strings.ToUpper(a)
}

func PrintReport(r ScanReport) {
	fmt.Println("\n╔══════════════════════════════════════════╗")
	fmt.Println("║       NETWORK SECURITY AUDIT REPORT      ║")
	fmt.Println("╚══════════════════════════════════════════╝")
	fmt.Printf("  Target    : %s\n", r.Target)
	fmt.Printf("  Scanned   : %s\n", r.ScannedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Score     : %d/100 [%s]\n\n", r.Score, r.RiskLabel)

	fmt.Printf("  Critical  : %d\n", len(r.Critical))
	fmt.Printf("  High      : %d\n", len(r.High))
	fmt.Printf("  Medium    : %d\n", len(r.Medium))
	fmt.Printf("  Low       : %d\n\n", len(r.Low))

	if len(r.Critical) > 0 {
		fmt.Println("── CRITICAL FINDINGS ──────────────────────")
		for _, f := range r.Critical {
			fmt.Printf("  %s:%d  %s %s\n", f.IP, f.Port, f.Service, f.Version)
			for _, c := range f.CVEs {
				fmt.Printf("    → %s [%.1f] %s\n", c.ID, c.Score, c.FixAdvice)
			}
		}
	}

	if len(r.High) > 0 {
		fmt.Println("\n── HIGH FINDINGS ───────────────────────────")
		for _, f := range r.High {
			fmt.Printf("  %s:%d  %s %s\n", f.IP, f.Port, f.Service, f.Version)
			for _, c := range f.CVEs {
				fmt.Printf("    → %s [%.1f] %s\n", c.ID, c.Score, c.FixAdvice)
			}
		}
	}
}