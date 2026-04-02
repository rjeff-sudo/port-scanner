# Port Scanner & Network Monitor

A concurrent TCP port scanner and continuous network monitor built in Go. Scans a range of IPs and ports, detects open ones using TCP connect scanning, grabs service banners, performs OS detection, and reports results in a clean colored table. Built as part of learning systems programming and network tooling in Go.

---

## Tools

This project contains two separate binaries:

- **port-scanner** — scans a network once and exits
- **network-monitor** — continuously monitors a network and alerts on changes

---

## Features

- TCP connect scanning with concurrent worker pool
- Banner grabbing — identifies what service is running on each open port
- OS detection from banners — labels devices as Ubuntu, Debian, MikroTik, Windows, iOS, Embedded/IoT etc
- Reverse DNS lookup — resolves hostnames for discovered devices
- Live progress bar during scanning
- Colored, sorted summary table output
- Port profiles — scan by name instead of numbers
- Verbose mode — show closed and filtered ports
- Rate limiting — control probes per second
- Save results to `.json`, `.csv`, or `.txt`
- Network state persistence — monitor remembers the network between restarts
- Auto-named state files per network — switch networks without conflicts

---

## Project Structure

```
port-scanner/
├── cmd/
│   ├── scanner/
│   │   └── main.go       → port scanner entry point
│   └── monitor/
│       └── main.go       → network monitor entry point
├── scanner/
│   ├── scanner.go        → TCP scanning, banner grabbing, worker pool
│   ├── ip.go             → IP parsing, range generation, reverse DNS
│   ├── result.go         → result struct, table output, file saving
│   └── os.go             → OS detection from banners
├── monitor/
│   ├── monitor.go        → change detection, monitoring loop
│   └── state.go          → network snapshots, state persistence
├── go.mod
├── go.sum
└── README.md
```

---

## Requirements

- Go 1.21 or higher
- Linux / macOS
- Network access to target range

---

## Installation

### On Any Machine

```bash
# Clone the repo
git clone https://github.com/rjeff-sudo/port-scanner.git
cd port-scanner

# Fix GOPATH if needed (especially on shared/lab machines)
export GOPATH=$HOME/go
export GOMODCACHE=$HOME/go/pkg/mod

# Make it permanent
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export GOMODCACHE=$HOME/go/pkg/mod' >> ~/.bashrc
source ~/.bashrc

# Build both tools
go build ./...
go build -o port-scanner ./cmd/scanner
go build -o network-monitor ./cmd/monitor
```

Go will automatically download all dependencies on first build.

---

## Usage

### Port Scanner

```bash
# Scan a single machine
./port-scanner -target 192.168.1.1 -ports 22,80,443 -workers 100

# Scan a network range
./port-scanner -target 192.168.1.1-192.168.1.254 -ports 22,80,443 -workers 200

# Use a port profile
./port-scanner -target 192.168.1.1-192.168.1.254 -ports common
./port-scanner -target 192.168.1.1-192.168.1.254 -ports web
./port-scanner -target 192.168.1.1-192.168.1.254 -ports db
./port-scanner -target 192.168.1.1-192.168.1.254 -ports ssh

# Scan all ports on a single machine
./port-scanner -target 192.168.1.1 -ports 1-65535 -workers 500

# Rate limited scan
./port-scanner -target 192.168.1.1-192.168.1.254 -ports common -rate 100

# Save results to file
./port-scanner -target 192.168.1.1-192.168.1.254 -ports common -output results.json
./port-scanner -target 192.168.1.1-192.168.1.254 -ports common -output results.csv

# Verbose mode (show closed ports)
./port-scanner -target 192.168.1.1 -ports common -v
```

#### Port Scanner Flags

| Flag | Default | Description |
|---|---|---|
| `-target` | required | IP or range (e.g. `192.168.1.1` or `192.168.1.1-192.168.1.254`) |
| `-ports` | `common` | Port range, list, or profile (`common/web/db/ssh`) |
| `-workers` | `100` | Number of concurrent workers |
| `-timeout` | `1` | Connection timeout in seconds |
| `-rate` | `0` | Max probes per second (0 = unlimited) |
| `-output` | `` | Save results to file (`.json`, `.csv`, `.txt`) |
| `-v` | `false` | Verbose — show closed ports |

---

### Port Profiles

| Profile | Ports |
|---|---|
| `common` | 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080 |
| `web` | 80, 443, 8080, 8443, 8000, 8888 |
| `db` | 3306, 5432, 6379, 27017, 1433, 5984 |
| `ssh` | 22, 2222, 521 |

---

### Network Monitor

```bash
# Monitor a network every 60 seconds
./network-monitor -target 192.168.1.1-192.168.1.254 -ports 22,80,443 -workers 200 -interval 60

# Monitor every 20 seconds
./network-monitor -target 192.168.1.1-192.168.1.254 -ports 22,80,443 -workers 200 -interval 20

# Use a custom state file
./network-monitor -target 192.168.1.1-192.168.1.254 -ports 22,80,443 -state office.json

# Monitor a different network (state files are auto-named per network)
./network-monitor -target 10.0.0.1-10.0.0.254 -ports 22,80,443 -workers 200 -interval 60
```

#### Network Monitor Flags

| Flag | Default | Description |
|---|---|---|
| `-target` | required | IP or range to monitor |
| `-ports` | `22,80,443` | Ports to monitor |
| `-workers` | `100` | Number of concurrent workers |
| `-timeout` | `1` | Connection timeout in seconds |
| `-interval` | `60` | Scan interval in seconds |
| `-state` | auto | State file path (default: auto-named from target) |

---

## Example Output

```
Scanning 254 IP(s) across 3 port(s) with 200 workers...

HOST                 IP               PORT   STATUS     SERVICE                        OS
──────────────────────────────────────────────────────────────────────────────────────────
-                    192.168.89.2     22     open       SSH-2.0-ROSSSH                 MikroTik RouterOS
                                      80     open       -                              -
-                    192.168.89.12    80     open       Server: Caddy                  Linux (Caddy)
                                      443    open       -                              -
-                    192.168.89.13    22     open       SSH-2.0-OpenSSH_9.2p1 Debian   Debian
-                    192.168.89.165   22     open       SSH-2.0-dropbear_2015.67       Embedded/IoT
                                      80     open       Server: GoAhead-Webs           Embedded/IoT
LAP-092              192.168.89.190   22     open       SSH-2.0-OpenSSH_9.6p1 Ubuntu   Ubuntu
                                      80     open       Server: Apache/2.4.58 (Ubuntu) Ubuntu
──────────────────────────────────────────────────────────────────────────────────────────
Found 121 open port(s) across 62 host(s)
```

### Monitor Output

```
--- Network Monitor Started ---
Target: 192.168.89.1-192.168.89.254 | Interval: 20s | State: state_192_168_89_1_192_168_89_254.json

[*] No previous state found. Establishing baseline...
[+] Baseline established — 63 device(s) found

[15:22:30] Scanning...
[15:22:33] 2 change(s) detected:
  [NEW DEVICE]   192.168.89.88:22 -> SSH-2.0-OpenSSH_9.6p1 Ubuntu
  [LOST DEVICE]  192.168.89.34:80 -> Server: Apache/2.4.58 (Ubuntu)

[15:22:50] Scanning...
[15:22:53] No changes detected
```

---

## OS Detection

The scanner identifies operating systems from SSH and HTTP banners:

| Banner | Detected OS |
|---|---|
| `SSH-2.0-OpenSSH_x.x Ubuntu` | Ubuntu |
| `SSH-2.0-OpenSSH_x.x Debian` | Debian |
| `SSH-2.0-ROSSSH` | MikroTik RouterOS |
| `SSH-2.0-dropbear` | Embedded/IoT |
| `Server: Microsoft-IIS` | Windows Server |
| `Server: GCDWebServer` | iOS |
| `Server: GoAhead-Webs` | Embedded/IoT |
| `Server: Caddy` | Linux (Caddy) |
| `Server: Apache` | Linux (Apache) |
| `Server: nginx` | Linux (Nginx) |

---

## Important Note

Only scan networks and devices you own or have explicit permission to scan. Unauthorized port scanning may be illegal under computer misuse laws in your country.

---

## Built With

- [Go](https://golang.org) — systems programming language
- [fatih/color](https://github.com/fatih/color) — terminal colors
- [schollz/progressbar](https://github.com/schollz/progressbar) — live progress bar

---

## Author

Jeff — Zone01 Kisumu 