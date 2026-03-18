package monitor

import (
	"encoding/json"
	"os"
	"time"

	"port-scanner/scanner"
)

// Snapshot represents the network state at a point in time
type Snapshot struct {
	Timestamp time.Time                       `json:"timestamp"`
	Devices   map[string]map[int]string       `json:"devices"` // IP → port → banner
}

// NewSnapshot creates a snapshot from scan results
func NewSnapshot(results []scanner.Result) Snapshot {
	devices := make(map[string]map[int]string)

	for _, r := range results {
		if r.Status == "open" {
			if devices[r.IP] == nil {
				devices[r.IP] = make(map[int]string)
			}
			devices[r.IP][r.Port] = r.Banner
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