package model

import (
	"encoding/json"
	"net/netip"
	"time"
)

type TelemetryBatch struct {
	SchemaVersion int         `json:"schema_version"`
	Agent         AgentInfo   `json:"agent"`
	Batch         BatchHeader `json:"batch"`
	Events        []RawEvent  `json:"events"`
}

type AgentInfo struct {
	AgentID      string           `json:"agent_id"`
	BootID       string           `json:"boot_id"`
	Hostname     string           `json:"hostname"`
	AgentVersion string           `json:"agent_version,omitempty"`
	Kernel       string           `json:"kernel,omitempty"`
	Interfaces   []AgentInterface `json:"interfaces,omitempty"`
}

type AgentInterface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac,omitempty"`
	IPv4 []string `json:"ipv4,omitempty"`
	IPv6 []string `json:"ipv6,omitempty"`
}

type BatchHeader struct {
	Seq              uint64    `json:"seq"`
	SentAt           time.Time `json:"sent_at"`
	DroppedSinceLast uint64    `json:"dropped_since_last"`
}

type AgentAssessment struct {
	Rule     string `json:"rule,omitempty"`
	Severity string `json:"severity,omitempty"`
}

type RawEvent struct {
	Type            string           `json:"type"`
	TS              time.Time        `json:"ts"`
	PID             uint32           `json:"pid"`
	PPID            uint32           `json:"ppid"`
	UID             uint32           `json:"uid"`
	GID             uint32           `json:"gid"`
	Comm            string           `json:"comm"`
	Data            json.RawMessage  `json:"data"`
	AgentAssessment *AgentAssessment `json:"agent_assessment,omitempty"`
}

type NormalizedEvent struct {
	ID            int64      `json:"id"`
	BatchID       int64      `json:"batch_id"`
	AgentID       string     `json:"agent_id"`
	DeviceID      *int64     `json:"device_id,omitempty"`
	BootID        string     `json:"boot_id"`
	Type          string     `json:"type"`
	Category      string     `json:"category"`
	Action        string     `json:"action"`
	TS            time.Time  `json:"ts"`
	PID           uint32     `json:"pid"`
	PPID          uint32     `json:"ppid"`
	UID           uint32     `json:"uid"`
	GID           uint32     `json:"gid"`
	Comm          string     `json:"comm"`
	Image         string     `json:"image,omitempty"`
	DstIP         netip.Addr `json:"dst_ip,omitempty"`
	DstPort       uint16     `json:"dst_port,omitempty"`
	TargetPID     uint32     `json:"target_pid,omitempty"`
	Path          string     `json:"path,omitempty"`
	Command       string     `json:"command,omitempty"`
	OldUID        uint32     `json:"old_uid,omitempty"`
	TargetUID     uint32     `json:"target_uid,omitempty"`
	DataJSON      string     `json:"data_json,omitempty"`
	AgentRule     string     `json:"agent_rule,omitempty"`
	AgentSeverity string     `json:"agent_severity,omitempty"`
}

type AgentRecord struct {
	AgentID            string           `json:"agent_id"`
	DeviceID           *int64           `json:"device_id,omitempty"`
	Hostname           string           `json:"hostname"`
	AgentVersion       string           `json:"agent_version,omitempty"`
	Kernel             string           `json:"kernel,omitempty"`
	TokenSHA256        []byte           `json:"-"`
	BootID             string           `json:"boot_id,omitempty"`
	EnrolledAt         time.Time        `json:"enrolled_at"`
	LastHeartbeat      *time.Time       `json:"last_heartbeat,omitempty"`
	EventsDroppedTotal uint64           `json:"events_dropped_total"`
	Status             string           `json:"status"` // active, revoked, conflict
	Interfaces         []AgentInterface `json:"interfaces,omitempty"`
}

type AgentEnrollRequest struct {
	AgentID         string `json:"agent_id"`
	Hostname        string `json:"hostname"`
	EnrollmentToken string `json:"enrollment_token"`
}

type AgentEnrollResponse struct {
	AgentToken string `json:"agent_token"`
}

type TelemetryResponse struct {
	Accepted  int  `json:"accepted"`
	Rejected  int  `json:"rejected"`
	Duplicate bool `json:"duplicate,omitempty"`
}
