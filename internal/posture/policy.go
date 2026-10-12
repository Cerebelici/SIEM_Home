package posture

import "time"

// Policy specifies versioned parameters for deterministic posture and CVSS scoring.
type Policy struct {
	Version           string             `json:"version"`
	Gamma             float64            `json:"gamma"`
	Lambda            float64            `json:"lambda"`
	UnknownCVSS       float64            `json:"unknown_cvss"`
	ExploitMultiplier float64            `json:"exploit_multiplier"`
	PenaltyCap        float64            `json:"penalty_cap"`
	IncidentPoints    map[string]float64 `json:"incident_points"`
	ActiveWindow      time.Duration      `json:"active_window"`
}

// DefaultPolicy is the standard cvss-agg-v1 scoring policy.
var DefaultPolicy = Policy{
	Version:           "cvss-agg-v1",
	Gamma:             0.5,
	Lambda:            0.4,
	UnknownCVSS:       4.0,
	ExploitMultiplier: 1.2,
	PenaltyCap:        30.0,
	IncidentPoints: map[string]float64{
		"CRITICAL": 15.0,
		"HIGH":     8.0,
		"MEDIUM":   3.0,
		"LOW":      1.0,
	},
	ActiveWindow: 24 * time.Hour,
}
