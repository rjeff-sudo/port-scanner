package scanner

import "strings"

// DetectOS attempts to identify the OS from SSH and HTTP banners
func DetectOS(banner string) string {
	if banner == "" {
		return ""
	}

	banner = strings.ToLower(banner)

	// SSH based detection
	switch {
	case strings.Contains(banner, "ubuntu"):
		return "Ubuntu"
	case strings.Contains(banner, "debian"):
		return "Debian"
	case strings.Contains(banner, "centos"):
		return "CentOS"
	case strings.Contains(banner, "fedora"):
		return "Fedora"
	case strings.Contains(banner, "rosssh"):
		return "MikroTik RouterOS"
	case strings.Contains(banner, "dropbear"):
		return "Embedded/IoT"
	case strings.Contains(banner, "freebsd"):
		return "FreeBSD"

	// HTTP based detection
	case strings.Contains(banner, "microsoft-iis"):
		return "Windows Server"
	case strings.Contains(banner, "gcdwebserver"):
		return "iOS"
	case strings.Contains(banner, "goahead"):
		return "Embedded/IoT"
	case strings.Contains(banner, "jetty"):
		return "Java Application Server"
	case strings.Contains(banner, "caddy"):
		return "Linux (Caddy)"
	case strings.Contains(banner, "apache"):
		return "Linux (Apache)"
	case strings.Contains(banner, "nginx"):
		return "Linux (Nginx)"
	}

	return ""
}