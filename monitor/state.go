package monitor

import (
	"encoding/json"
	"os"
	"time"

	"port-scanner/scanner"
)

// Snapshot represents the network state at a point in time
type Snapshot struct {
	Timestamp time.Time        `json:"timestamp"`
	Devices   map[string][]int `json:"devices"` // IP → list of open ports
}

// NewSnapshot creates a snapshot from scan results
func NewSnapshot(results []scanner.Result) Snapshot {
	devices := make(map[string][]int)

	for _, r := range results {
		if r.Status == "open" {
			devices[r.IP] = append(devices[r.IP], r.Port)
		}
	}

	return Snapshot{
		Timestamp: time.Now(),
		Devices:   devices,
	}
}

// SaveSnapshot saves the current snapshot to a JSON file on disk
func SaveSnapshot(s Snapshot, filepath string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, data, 0644)
}

// LoadSnapshot loads a previous snapshot from disk
func LoadSnapshot(filepath string) (Snapshot, error) {
	var s Snapshot
	data, err := os.ReadFile(filepath)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(data, &s)
	return s, err
}