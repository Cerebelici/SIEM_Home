# Cerberus - Network Sentinel & Vulnerability Auditor

Cerberus is an automated network sentinel built in Go for identifying active network hosts, auditing open services, and detecting known vulnerabilities (CVEs).

## Features

- **Automated Host Discovery (Cron: 30 min)**: Periodically scans local subnet to identify live devices, MAC addresses, hostnames, and vendors.
- **Service & CVE Vulnerability Auditing (Cron: 10 min)**: Audits open ports and queries Nmap vulnerability scripts (`vulners` / `vuln`) to correlate services with known CVEs and CVSS severity scores.
- **⚡ Reactive On-Demand Scanning**: Whenever a new device is discovered, an immediate vulnerability scan is launched for that target without waiting for the 10-minute scheduled cycle.
- **Persistent SQLite & JSON Export**: All devices, ports, CVEs, and scan histories are persisted in SQLite (with WAL mode enabled for high concurrency) and can be exported as structured JSON at any time.
- **RESTful API & Web Server**: Built with Go standard routing, CORS support, and JSON endpoints for frontend web or desktop dashboards.
- **Independent Goroutine Concurrency**: Discovery, periodic vulnerability scans, and reactive immediate scans run in separate, thread-safe goroutines with graceful shutdown handling.

---

## Architecture Overview

```
                          ┌────────────────────────┐
                          │   cmd/sentinel/main    │
                          │ (Wiring & Shutdown)    │
                          └───────────┬────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         ▼                            ▼                            ▼
┌──────────────────┐        ┌──────────────────┐        ┌──────────────────┐
│ internal/config  │        │ internal/storage │        │   internal/api   │
│ - Env / Defaults │        │ - SQLite (WAL)   │        │ - HTTP Router    │
│ - Subnet, Timers │        │ - Models & CRUD  │        │ - REST Endpoints │
└──────────────────┘        │ - JSON Export    │        │ - CORS & Logging │
                            └─────────▲────────┘        └──────────────────┘
                                      │
                 ┌────────────────────┴────────────────────┐
                 │                                         │
        ┌──────────────────┐                      ┌──────────────────┐
        │internal/scheduler│                      │internal/discovery│
        │ - 30m Discovery  │                      │ - Host Discovery │
        │ - 10m Full Vuln  │                      │ - Detect New Devs│
        └────────┬─────────┘                      └────────┬─────────┘
                 │                                         │
                 │   [Immediate Vuln Scan for New Device]  │
                 │◀────────────────────────────────────────┘
                 │ (via buffered channel/worker)
                 ▼
        ┌──────────────────┐
        │ internal/scanner │
        │ - Nmap XML Parser│
        │ - Vuln/CVE Audits│
        │ - Output Models  │
        └──────────────────┘
```

---

## Quick Start

### Option 1: Run with Docker Compose (Recommended for isolated testbed)

The docker-compose setup creates an isolated test network (`172.28.0.0/24`) containing vulnerable targets (Nginx, Redis, DVWA) and the Cerberus Sentinel container:

```bash
docker compose up -d --build
```

Access the REST API at `http://localhost:8080`.

### Option 2: Run Locally on Host

1. Build the binary:
   ```bash
   go build -o bin/sentinel ./cmd/sentinel
   ```
2. Run the sentinel:
   ```bash
   CERBERUS_SUBNET=172.28.0.0/24 CERBERUS_PORT=8080 ./bin/sentinel
   ```

---

## Configuration

Settings can be customized via environment variables:

| Variable | Description | Default |
|---|---|---|
| `CERBERUS_PORT` | HTTP Server port | `8080` |
| `CERBERUS_HOST` | HTTP Server bind address | `0.0.0.0` |
| `CERBERUS_DB_PATH` | Path to SQLite database file | `cerberus.db` |
| `CERBERUS_SUBNET` | Target CIDR to discover | `172.28.0.0/24` |
| `CERBERUS_DISCOVERY_INTERVAL` | Network discovery scan frequency | `30m` |
| `CERBERUS_VULN_INTERVAL` | Full network vulnerability scan frequency | `10m` |
| `CERBERUS_NMAP_PATH` | Path to nmap binary | `nmap` |
| `CERBERUS_VULN_SCRIPT` | NSE vulnerability script | `vulners` |
| `CERBERUS_UNPRIVILEGED` | Force TCP connect unprivileged mode | `true` |
| `CERBERUS_SCAN_TIMEOUT` | Max timeout per scan execution | `15m` |

---

## REST API Reference

All responses are formatted in JSON. CORS is enabled for all origins (`*`) by default.

### Inventory & Devices

- **`GET /api/devices`**: Lists all tracked devices with service and vulnerability counts.
  - Query parameter: `?status=up` or `?status=down`
- **`GET /api/devices/{id}`**: Returns full device details including all detected open ports/services and CVE vulnerabilities.
- **`GET /api/services`**: Lists open services detected across the entire network.
- **`GET /api/vulnerabilities`**: Lists all detected CVE vulnerabilities.
  - Query parameter: `?severity=CRITICAL` / `HIGH` / `MEDIUM` / `LOW`

### Scans & Execution Controls

- **`GET /api/scans`**: Returns historical scan execution records.
  - Query parameter: `?limit=50`
- **`POST /api/scans/discovery/trigger`**: Manually triggers an immediate network discovery scan in the background.
- **`POST /api/scans/vulnerability/trigger`**: Manually triggers an immediate vulnerability audit across active hosts.

### Dashboard Status & JSON Export

- **`GET /api/status`**: Live sentinel stats (uptime, total/active devices, services, vulnerabilities, scheduler next run times, active scanning flags).
- **`GET /api/export/json`**: Downloads a complete network inventory snapshot formatted as JSON.
- **`GET /health`**: Simple healthcheck endpoint (`{"status": "ok"}`).

---

## Testing

Run unit and integration test suites:

```bash
go test -v ./...
go test -race ./...
```

---

## Building & Desktop Application

Cerberus Sentinel can run either as a headless background daemon or as a desktop GUI application powered by Wails v2.

### Build Targets

```bash
# Build headless background sentinel binary (CGO-free)
make build-headless

# Build Wails desktop application (Linux/macOS)
make build-desktop

# Apply raw socket capability to nmap for privileged mode without root
make setcap-nmap
```

### Desktop Application Dependencies (Linux / Ubuntu 24.04)

To build the Wails v2 desktop application on Linux, ensure the following system packages and Wails CLI are installed:

```bash
sudo apt-get update && sudo apt-get install -y \
  libgtk-3-dev \
  libwebkit2gtk-4.1-dev \
  pkg-config \
  build-essential

go install github.com/wailsapp/wails/v2/cmd/wails@latest
```