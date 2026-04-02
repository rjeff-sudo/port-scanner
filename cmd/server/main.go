package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"port-scanner/audit"
	"port-scanner/scanner"
	"time"
)

// ScanRequest is what the frontend sends
type ScanRequest struct {
	Target  string `json:"target"`
	Ports   string `json:"ports"`
	Workers int    `json:"workers"`
}

// ScanResponse is what we send back
type ScanResponse struct {
	Success bool             `json:"success"`
	Error   string           `json:"error,omitempty"`
	Report  *audit.ScanReport `json:"report,omitempty"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// routes
	http.HandleFunc("/", serveHome)
	http.HandleFunc("/api/scan", handleScan)
	http.HandleFunc("/api/health", handleHealth)

	// serve static files
	fs := http.FileServer(http.Dir("web/static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	fmt.Printf("🚀 NetAudit server running on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func serveHome(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "web/static/index.html")
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	// only allow POST
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// decode request
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(ScanResponse{
			Success: false,
			Error:   "invalid request body",
		})
		return
	}

	// validate
	if req.Target == "" {
		json.NewEncoder(w).Encode(ScanResponse{
			Success: false,
			Error:   "target is required",
		})
		return
	}

	if req.Workers == 0 {
		req.Workers = 100
	}

	if req.Ports == "" {
		req.Ports = "22,80,443"
	}

	// parse ports
	ports, err := scanner.ParsePorts(req.Ports)
	if err != nil {
		json.NewEncoder(w).Encode(ScanResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid ports: %s", err),
		})
		return
	}

	// parse IPs
	ips, err := scanner.ParseIPs(req.Target)
	if err != nil {
		json.NewEncoder(w).Encode(ScanResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid target: %s", err),
		})
		return
	}

	// run scan
	timeout := 1 * time.Second
	results := scanner.RunWorkerPool(ips, ports, req.Workers, timeout, 0)

	// convert scanner.Result to audit.ScannerResult
	var auditResults []audit.ScannerResult
	for _, r := range results {
		auditResults = append(auditResults, audit.ScannerResult{
			IP:       r.IP,
			Port:     r.Port,
			Status:   r.Status,
			Banner:   r.Banner,
			Hostname: r.Hostname,
			OS:       r.OS,
		})
	}

	// run audit
	report := audit.AuditResults(req.Target, auditResults)

	json.NewEncoder(w).Encode(ScanResponse{
		Success: true,
		Report:  &report,
	})
}