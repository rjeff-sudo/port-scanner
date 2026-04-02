package audit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// CVE holds a single vulnerability finding
type CVE struct {
	ID          string
	Description string
	Severity    string
	Score       float64
	FixAdvice   string
}

// Finding holds a banner matched with its CVEs
type Finding struct {
	IP      string
	Port    int
	Banner  string
	Service string
	Version string
	CVEs    []CVE
	Risk    string // CRITICAL / HIGH / MEDIUM / LOW / INFO
}

// NVD API response structures
type nvdResponse struct {
	Vulnerabilities []struct {
		Cve struct {
			ID          string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CvssMetricV2 []struct {
					CvssData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// ParseBanner extracts a searchable service+version string from a raw banner
func ParseBanner(banner string) (service, version, query string) {
	banner = strings.TrimSpace(banner)

	// SSH banners: SSH-2.0-OpenSSH_7.4 or SSH-2.0-dropbear_2015.67
	if strings.HasPrefix(banner, "SSH-") {
		parts := strings.SplitN(banner, "-", 3)
		if len(parts) == 3 {
			software := parts[2] // e.g. OpenSSH_7.4 or dropbear_2015.67
			if idx := strings.Index(software, "_"); idx != -1 {
				service = software[:idx]   // OpenSSH
				version = software[idx+1:] // 7.4
				// strip Ubuntu/Debian suffixes e.g. "9.6p1 Ubuntu-3ubuntu13.14"
				if spaceIdx := strings.Index(version, " "); spaceIdx != -1 {
					version = version[:spaceIdx]
				}
				query = service + " " + version
				return
			}
		}
	}

	// HTTP banners: Server: Apache/2.4.58 (Ubuntu)
	if strings.HasPrefix(banner, "Server:") {
		banner = strings.TrimPrefix(banner, "Server:")
		banner = strings.TrimSpace(banner)
		// strip parenthetical e.g. "(Ubuntu)"
		if idx := strings.Index(banner, "("); idx != -1 {
			banner = strings.TrimSpace(banner[:idx])
		}
		// split on /
		if idx := strings.Index(banner, "/"); idx != -1 {
			service = strings.TrimSpace(banner[:idx])
			version = strings.TrimSpace(banner[idx+1:])
			query = service + " " + version
			return
		}
		service = banner
		query = banner
		return
	}

	// fallback
	re := regexp.MustCompile(`([A-Za-z][A-Za-z0-9\-]+)[/_\s](\d+[\d.]+)`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) >= 3 {
		service = matches[1]
		version = matches[2]
		query = service + " " + version
		return
	}

	service = banner
	query = banner
	return
}

// QueryNVD queries the NVD API for a given search keyword
func QueryNVD(query string) ([]CVE, error) {
	apiKey := os.Getenv("NVD_API_KEY")

	baseURL := "https://services.nvd.nist.gov/rest/json/cves/2.0"
	params := url.Values{}
	params.Set("keywordSearch", query)
	params.Set("resultsPerPage", "5")

	fullURL := baseURL + "?" + params.Encode()

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, err
	}

	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	var nvd nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvd); err != nil {
		return nil, err
	}

	var cves []CVE
	for _, v := range nvd.Vulnerabilities {
		cve := CVE{ID: v.Cve.ID}

		// get English description
		for _, d := range v.Cve.Descriptions {
			if d.Lang == "en" {
				// truncate long descriptions
				if len(d.Value) > 200 {
					cve.Description = d.Value[:200] + "..."
				} else {
					cve.Description = d.Value
				}
				break
			}
		}

		// get severity score — prefer v3.1, fall back to v2
		if len(v.Cve.Metrics.CvssMetricV31) > 0 {
			cve.Score = v.Cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
			cve.Severity = v.Cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		} else if len(v.Cve.Metrics.CvssMetricV2) > 0 {
			cve.Score = v.Cve.Metrics.CvssMetricV2[0].CvssData.BaseScore
			cve.Severity = v.Cve.Metrics.CvssMetricV2[0].BaseSeverity
		}

		cve.FixAdvice = fixAdvice(cve.Severity)
		cves = append(cves, cve)
	}

	return cves, nil
}

// CheckBanner parses a banner and queries NVD, returning a Finding
func CheckBanner(ip string, port int, banner string) Finding {
	service, version, query := ParseBanner(banner)

	finding := Finding{
		IP:      ip,
		Port:    port,
		Banner:  banner,
		Service: service,
		Version: version,
		Risk:    "INFO",
	}

	if query == "" || query == "-" {
		return finding
	}

	cves, err := QueryNVD(query)
	if err != nil {
		finding.Risk = "INFO"
		return finding
	}

	finding.CVEs = cves
	finding.Risk = calculateRisk(cves)
	return finding
}

// calculateRisk returns the highest risk level from a list of CVEs
func calculateRisk(cves []CVE) string {
	highest := "INFO"
	order := map[string]int{
		"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
	}
	for _, c := range cves {
		sev := strings.ToUpper(c.Severity)
		if order[sev] > order[highest] {
			highest = sev
		}
	}
	return highest
}

// fixAdvice returns a plain English fix recommendation based on severity
func fixAdvice(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "Patch or upgrade immediately. This vulnerability is actively exploited."
	case "HIGH":
		return "Schedule upgrade within 7 days. High risk of exploitation."
	case "MEDIUM":
		return "Plan upgrade in next maintenance window."
	case "LOW":
		return "Monitor and upgrade when convenient."
	default:
		return "Review and assess whether this service needs to be exposed."
	}
}