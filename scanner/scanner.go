package scanner

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
)

// PortProfiles defines named port sets
var PortProfiles = map[string][]int{
	"common": {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080},
	"web":    {80, 443, 8080, 8443, 8000, 8888},
	"db":     {3306, 5432, 6379, 27017, 1433, 5984},
	"ssh":    {22, 2222, 521},
}

type Job struct {
	IP   string
	Port int
}

// fastPorts are well known ports that respond quickly
var fastPorts = map[int]bool{
	22: true, 80: true, 443: true, 21: true,
	25: true, 53: true, 23: true, 3306: true,
	5432: true, 6379: true, 8080: true, 8443: true,
}

// portTimeout returns a shorter timeout for known ports
func portTimeout(port int, defaultTimeout time.Duration) time.Duration {
	if fastPorts[port] {
		return 500 * time.Millisecond
	}
	return defaultTimeout
}

// OptimalWorkers calculates best worker count based on job size
func OptimalWorkers(jobs int, requested int) int {
	if requested > jobs {
		return jobs
	}
	if requested > 500 {
		return 500
	}
	return requested
}

// PingHost checks if a host is alive using system ping
func PingHost(ip string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip)
	err := cmd.Run()
	return err == nil
}

// GrabBanner attempts to grab a service banner from an open connection
func GrabBanner(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	banner, err := reader.ReadString('\n')
	if err == nil && strings.TrimSpace(banner) != "" {
		return strings.TrimSpace(banner)
	}

	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", conn.RemoteAddr())
	conn.SetReadDeadline(time.Now().Add(timeout))

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(line)
		}
		if line == "" {
			break
		}
	}

	return ""
}

// ScanPort attempts a TCP connection and grabs a banner if port is open
func ScanPort(ip string, port int, timeout time.Duration) Result {
	timeout  = portTimeout(port, timeout)
	address := fmt.Sprintf("%s:%d", ip, port)
      if strings.Contains(ip, ":") {
         address = fmt.Sprintf("[%s]:%d", ip, port)
      }
	conn, err := net.DialTimeout("tcp", address, timeout)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return Result{IP: ip, Port: port, Status: "filtered"}
		}
		return Result{IP: ip, Port: port, Status: "closed"}
	}
	defer conn.Close()

	banner   := GrabBanner(conn, timeout)
	hostname := LookupHostname(ip)
	os       := DetectOS(banner)
	return Result{IP: ip, Port: port, Status: "open", Banner: banner, Hostname: hostname, OS: os}
}

// RunWorkerPool spins up a pool of goroutines to scan concurrently
func RunWorkerPool(ips []string, ports []int, workers int, timeout time.Duration, rateLimit int) []Result {
	total   := len(ips) * len(ports)
	workers  = OptimalWorkers(total, workers)

	jobs    := make(chan Job, total)
	results := make(chan Result, total)

	// Rate limiter
	var rateLimiter <-chan time.Time
	if rateLimit > 0 {
		rateLimiter = time.NewTicker(time.Second / time.Duration(rateLimit)).C
	} else {
		ch := make(chan time.Time)
		close(ch)
		rateLimiter = ch
	}

	bar := progressbar.NewOptions(total,
		progressbar.OptionSetDescription("Scanning..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(40),
		progressbar.OptionClearOnFinish(),
	)

	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				<-rateLimiter
				results <- ScanPort(job.IP, job.Port, timeout)
				bar.Add(1)
			}
		}()
	}

	for _, ip := range ips {
		for _, port := range ports {
			jobs <- Job{IP: ip, Port: port}
		}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var scanResults []Result
	for r := range results {
		scanResults = append(scanResults, r)
	}

	return scanResults
}