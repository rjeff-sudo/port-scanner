package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Job represents a single unit of work — one IP:port combination to scan
type Job struct {
	IP   string
	Port int
}

// ScanPort attempts a TCP connection to a single IP:port
// Returns a Result indicating whether the port is open, closed, or filtered
func ScanPort(ip string, port int, timeout time.Duration) Result {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)

	if err != nil {
		// Check if it was a timeout (filtered) or a refusal (closed)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return Result{IP: ip, Port: port, Status: "filtered"}
		}
		return Result{IP: ip, Port: port, Status: "closed"}
	}

	conn.Close()
	return Result{IP: ip, Port: port, Status: "open"}
}

// RunWorkerPool spins up a pool of goroutines to scan all IP:port combinations concurrently
func RunWorkerPool(ips []string, ports []int, workers int, timeout time.Duration) []Result {
	jobs := make(chan Job, len(ips)*len(ports))
	results := make(chan Result, len(ips)*len(ports))

	var wg sync.WaitGroup

	// Launch worker goroutines
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				results <- ScanPort(job.IP, job.Port, timeout)
			}
		}()
	}

	// Feed all jobs into the jobs channel
	for _, ip := range ips {
		for _, port := range ports {
			jobs <- Job{IP: ip, Port: port}
		}
	}
	close(jobs) // No more jobs — workers will finish and exit

	// Wait for all workers to finish then close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect all results
	var scanResults []Result
	for r := range results {
		scanResults = append(scanResults, r)
	}

	return scanResults
}