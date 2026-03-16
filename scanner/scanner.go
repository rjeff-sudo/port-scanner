package scanner

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
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
	return Result{IP: ip, Port: port, Status: "open", Banner: banner}
}

// RunWorkerPool spins up a pool of goroutines to scan concurrently
func RunWorkerPool(ips []string, ports []int, workers int, timeout time.Duration) []Result {
	jobs := make(chan Job, len(ips)*len(ports))
	results := make(chan Result, len(ips)*len(ports))

	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				results <- ScanPort(job.IP, job.Port, timeout)
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