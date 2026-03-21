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

type Job struct {
	IP   string
	Port int
}

// GrabBanner attempts to grab a service banner from an open connection
func GrabBanner(conn net.Conn, timeout time.Duration) string {
	// Set deadline for reading
	conn.SetReadDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// First try reading — passive services speak first (SSH, FTP, SMTP)
	banner, err := reader.ReadString('\n')
	if err == nil && strings.TrimSpace(banner) != "" {
		return strings.TrimSpace(banner)
	}

	// Nothing came back — try speaking first with an HTTP request
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", conn.RemoteAddr())
	conn.SetReadDeadline(time.Now().Add(timeout))

	// Read response and look for Server header
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(line)
		}
		// Stop after headers
		if line == "" {
			break
		}
	}

	return ""
}

// PingHost checks if a host is alive using system ping
// Returns true if host responds, false if unreachable
func PingHost(ip string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip)
	err := cmd.Run()
	return err == nil
}

// ScanPort attempts a TCP connection and grabs a banner if port is open
func ScanPort(ip string, port int, timeout time.Duration) Result {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return Result{IP: ip, Port: port, Status: "filtered"}
		}
		return Result{IP: ip, Port: port, Status: "closed"}
	}
	defer conn.Close()

	banner := GrabBanner(conn, timeout)
	hostname := LookupHostname(ip) // new
	return Result{IP: ip, Port: port, Status: "open", Banner: banner, Hostname: hostname}
}

func RunWorkerPool(ips []string, ports []int, workers int, timeout time.Duration) []Result {
	total := len(ips) * len(ports)
	jobs := make(chan Job, total)
	results := make(chan Result, total)

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