package model

import "time"

// Device represents a network host discovered by Cerberus.
type Device struct {
	ID                   int64           `json:"id"`
	IP                   string          `json:"ip"`
	MAC                  string          `json:"mac,omitempty"`
	Hostname             string          `json:"hostname,omitempty"`
	Vendor               string          `json:"vendor,omitempty"`
	Status               string          `json:"status"` // "up" or "down"
	FirstSeen            time.Time       `json:"first_seen"`
	LastSeen             time.Time       `json:"last_seen"`
	ServicesCount        int             `json:"services_count"`
	VulnerabilitiesCount int             `json:"vulnerabilities_count"`
	Services             []Service       `json:"services,omitempty"`
	Vulnerabilities      []Vulnerability `json:"vulnerabilities,omitempty"`
}

// Service represents a network service running on an open port of a device.
type Service struct {
	ID              int64           `json:"id"`
	DeviceID        int64           `json:"device_id"`
	DeviceIP        string          `json:"device_ip,omitempty"`
	Port            int             `json:"port"`
	Protocol        string          `json:"protocol"` // "tcp" or "udp"
	ServiceName     string          `json:"service_name,omitempty"`
	Product         string          `json:"product,omitempty"`
	Version         string          `json:"version,omitempty"`
	State           string          `json:"state"` // "open", "filtered", "closed"
	UpdatedAt       time.Time       `json:"updated_at"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// Vulnerability represents an identified CVE or security weakness.
type Vulnerability struct {
	ID           int64     `json:"id"`
	DeviceID     int64     `json:"device_id"`
	DeviceIP     string    `json:"device_ip,omitempty"`
	ServicePort  int       `json:"service_port"`
	CVEID        string    `json:"cve_id"`
	Title        string    `json:"title,omitempty"`
	Severity     string    `json:"severity"` // "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"
	CVSSScore    float64   `json:"cvss_score"`
	Description  string    `json:"description,omitempty"`
	ReferenceURL string    `json:"reference_url,omitempty"`
	DetectedAt   time.Time `json:"detected_at"`
}

// ScanLog records historical scans executed by Cerberus.
type ScanLog struct {
	ID           int64      `json:"id"`
	ScanType     string     `json:"scan_type"` // "discovery", "vulnerability", "immediate"
	Status       string     `json:"status"`    // "running", "completed", "failed"
	TargetSpec   string     `json:"target_spec"`
	HostsFound   int        `json:"hosts_found"`
	VulnsFound   int        `json:"vulns_found"`
	DurationMs   int64      `json:"duration_ms"`
	ErrorMessage string     `json:"error_message,omitempty"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
}

// Capabilities describes the operational abilities and constraints of the scanner environment.
type Capabilities struct {
	NmapPath      string   `json:"nmap_path"`
	NmapVersion   string   `json:"nmap_version"`
	VulnScriptOK  bool     `json:"vuln_script_ok"`
	RawSocket     bool     `json:"raw_socket"`
	EffectiveMode string   `json:"effective_mode"` // "privileged" | "unprivileged"
	Warnings      []string `json:"warnings,omitempty"`
}

// SystemStatus provides a live snapshot of the sentinel.
type SystemStatus struct {
	Uptime               string        `json:"uptime"`
	UptimeSeconds        int64         `json:"uptime_seconds"`
	ActiveDevices        int           `json:"active_devices"`
	TotalDevices         int           `json:"total_devices"`
	TotalServices        int           `json:"total_services"`
	TotalVulnerabilities int           `json:"total_vulnerabilities"`
	DiscoveryNextRun     *time.Time    `json:"discovery_next_run,omitempty"`
	VulnNextRun          *time.Time    `json:"vuln_next_run,omitempty"`
	IsDiscoveryRunning   bool          `json:"is_discovery_running"`
	IsVulnRunning        bool          `json:"is_vuln_running"`
	Capabilities         *Capabilities `json:"capabilities"`
}

// ExportData represents the complete network sentinel snapshot for JSON export.
type ExportData struct {
	ExportedAt           time.Time `json:"exported_at"`
	NetworkCIDR          string    `json:"network_cidr"`
	TotalDevices         int       `json:"total_devices"`
	TotalVulnerabilities int       `json:"total_vulnerabilities"`
	Devices              []Device  `json:"devices"`
}

// ScanHostResult holds parsed scan results for a single target host.
type ScanHostResult struct {
	IP              string
	MAC             string
	Vendor          string
	Hostname        string
	Status          string
	Services        []Service
	Vulnerabilities []Vulnerability
}

// DeviceScanRecord stores a historical snapshot of a device during a specific scan.
type DeviceScanRecord struct {
	ID           int64     `json:"id"`
	DeviceID     int64     `json:"device_id"`
	ScanID       int64     `json:"scan_id"`
	Status       string    `json:"status"` // "up" or "down"
	IsVulnerable bool      `json:"is_vulnerable"`
	VulnsCount   int       `json:"vulns_count"`
	MaxSeverity  string    `json:"max_severity"` // "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"
	RecordedAt   time.Time `json:"recorded_at"`
}

// ScanTick represents a point on the timeline scan line when an engine scan completed.
type ScanTick struct {
	ScanID     int64     `json:"scan_id"`
	Timestamp  time.Time `json:"timestamp"`
	ScanType   string    `json:"scan_type"`
	Status     string    `json:"status"`
	TargetSpec string    `json:"target_spec"`
	HostsFound int       `json:"hosts_found"`
	DurationMs int64     `json:"duration_ms"`
}

// TimelinePeriod represents a continuous activity interval for a device with uniform status and vulnerability metrics.
type TimelinePeriod struct {
	StartedAt              time.Time `json:"started_at"`
	EndedAt                time.Time `json:"ended_at"`
	Status                 string    `json:"status"`
	IsVulnerable           bool      `json:"is_vulnerable"`
	VulnsCount             int       `json:"vulns_count"`
	MaxSeverity            string    `json:"max_severity"`
	IsOngoing              bool      `json:"is_ongoing"`
	TransitionUncertaintyS int64     `json:"transition_uncertainty_s,omitempty"`
}

// TimelineDevice represents a device with its segmented activity periods for timeline visualization.
type TimelineDevice struct {
	DeviceID      int64            `json:"device_id"`
	IP            string           `json:"ip"`
	MAC           string           `json:"mac,omitempty"`
	Hostname      string           `json:"hostname,omitempty"`
	Vendor        string           `json:"vendor,omitempty"`
	CurrentStatus string           `json:"current_status"`
	Periods       []TimelinePeriod `json:"periods"`
}

// TimelineTimeWindow defines the bounds and high-level counts for a timeline query.
type TimelineTimeWindow struct {
	From         time.Time `json:"from"`
	To           time.Time `json:"to"`
	TotalScans   int       `json:"total_scans"`
	TotalDevices int       `json:"total_devices"`
}

// TimelineResponse is the complete payload returned by GET /api/timeline.
type TimelineResponse struct {
	TimeWindow TimelineTimeWindow `json:"time_window"`
	ScanTicks  []ScanTick         `json:"scan_ticks"`
	Devices    []TimelineDevice   `json:"devices"`
}
