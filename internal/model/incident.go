package model

import "time"

// Incident represents a deduplicated security incident produced by the real-time detection rule engine.
type Incident struct {
	ID               int64             `json:"id"`
	DeviceID         *int64            `json:"device_id,omitempty"`
	AgentID          string            `json:"agent_id"`
	RuleID           string            `json:"rule_id"`
	RulesetVersion   string            `json:"ruleset_version"`
	Title            string            `json:"title"`
	Severity         string            `json:"severity"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Score            float64           `json:"score"`
	MitreTactic      string            `json:"mitre_tactic,omitempty"`
	MitreTechnique   string            `json:"mitre_technique,omitempty"`
	PIDRoot          uint32            `json:"pid_root,omitempty"`
	DedupeKey        string            `json:"dedupe_key"`
	FirstSeenAt      time.Time         `json:"first_seen_at"`
	LastSeenAt       time.Time         `json:"last_seen_at"`
	HitCount         int               `json:"hit_count"`
	EvidenceEventIDs []int64           `json:"evidence_event_ids"`
	Status           string            `json:"status"` // "open", "acknowledged", "closed"
	EvidenceEvents   []NormalizedEvent `json:"evidence_events,omitempty"`
}

// IncidentFilter contains optional search and pagination parameters for querying incidents.
type IncidentFilter struct {
	Status   string
	Severity string
	DeviceID *int64
	From     *time.Time
	To       *time.Time
	Limit    int
	Offset   int
}
