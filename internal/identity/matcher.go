package identity

import (
	"context"
	"sort"
	"time"
)

// Action defines the matching decision outcome.
type Action string

const (
	ActionBind      Action = "bind"
	ActionCreateNew Action = "create_new"
	ActionConflict  Action = "conflict"
)

// Observation represents an observed network endpoint snapshot from a scan or agent update.
type Observation struct {
	IP         string
	MAC        string
	Hostname   string
	Ports      []string
	ObservedAt time.Time
}

// Candidate represents an existing device loaded for matching against an observation.
type Candidate struct {
	ID                 int64
	AssetUID           string
	CurrentIP          string
	MAC                string
	MACIsRandom        bool
	Hostname           string
	Ports              []string
	Managed            bool
	IdentityConfidence float64
	LastSeen           time.Time
	AgentInterfaces    []string
	AgentAlive         bool
	BoundAgentID       string
}

// CandidateStore abstracts database access for candidate retrieval.
type CandidateStore interface {
	GetCandidates(ctx context.Context, window time.Duration) ([]Candidate, error)
}

// Weights configures matching criteria scores and thresholds.
type Weights struct {
	MAC             float64
	IPLease         float64
	IPStale         float64
	Hostname        float64
	Ports           float64
	OUI             float64
	HostConflict    float64
	Threshold       float64
	Margin          float64
	LeaseWindow     time.Duration
	CandidateWindow time.Duration
}

// DefaultWeights returns standard matcher tuning per Architecture §2.1.
func DefaultWeights() Weights {
	return Weights{
		MAC:             40,
		IPLease:         30,
		IPStale:         10,
		Hostname:        25,
		Ports:           20,
		OUI:             5,
		HostConflict:    -15,
		Threshold:       50,
		Margin:          15,
		LeaseWindow:     24 * time.Hour,
		CandidateWindow: 30 * 24 * time.Hour,
	}
}

// Decision represents the output of the matching algorithm.
type Decision struct {
	Action           Action
	DeviceID         *int64
	Confidence       float64
	Reason           string
	Score            float64
	RunnerUpDeviceID *int64
	RunnerUpScore    float64
}

// Matcher performs deterministic device fingerprinting and reconciliation.
type Matcher struct {
	store   CandidateStore
	weights Weights
	clock   func() time.Time
}

// NewMatcher creates a Matcher instance.
func NewMatcher(store CandidateStore, weights Weights, clock ...func() time.Time) *Matcher {
	clk := func() time.Time { return time.Now().UTC() }
	if len(clock) > 0 && clock[0] != nil {
		clk = clock[0]
	}
	return &Matcher{
		store:   store,
		weights: weights,
		clock:   clk,
	}
}

type scoredCandidate struct {
	c     Candidate
	score float64
}

// Resolve evaluates an observation against candidate devices using the 3-step reconciliation algorithm.
func (m *Matcher) Resolve(ctx context.Context, o Observation) (Decision, error) {
	now := o.ObservedAt
	if now.IsZero() {
		now = m.clock()
	}

	normMAC := NormalizeMAC(o.MAC)
	normHost := NormalizeHostname(o.Hostname)

	candidates, err := m.store.GetCandidates(ctx, m.weights.CandidateWindow)
	if err != nil {
		return Decision{}, err
	}

	// Step 1 — Managed binding (deterministic, wins outright)
	var managedMatches []Candidate
	for _, c := range candidates {
		if c.Managed && c.AgentAlive {
			containsIP := false
			for _, ifaceIP := range c.AgentInterfaces {
				if ifaceIP == o.IP {
					containsIP = true
					break
				}
			}
			macMatches := (normMAC == "" || c.MAC == "" || normMAC == c.MAC)
			if containsIP && macMatches {
				managedMatches = append(managedMatches, c)
			}
		}
	}

	if len(managedMatches) == 1 {
		devID := managedMatches[0].ID
		return Decision{
			Action:     ActionBind,
			DeviceID:   &devID,
			Confidence: 1.0,
			Reason:     "agent_interface",
			Score:      100.0,
		}, nil
	} else if len(managedMatches) > 1 {
		return Decision{
			Action:     ActionConflict,
			Confidence: 0.0,
			Reason:     "ip_claimed_by_multiple_agents",
			Score:      0.0,
		}, nil
	}

	// Step 2 — Globally unique MAC (UAA)
	if normMAC != "" && !IsLocallyAdministered(normMAC) {
		for _, c := range candidates {
			if c.MAC == normMAC && !IsLocallyAdministered(c.MAC) {
				devID := c.ID
				return Decision{
					Action:     ActionBind,
					DeviceID:   &devID,
					Confidence: 1.0,
					Reason:     "uaa_mac",
					Score:      100.0,
				}, nil
			}
		}
	}

	// Step 3 — Weighted evidence over candidates C
	var scored []scoredCandidate
	for _, c := range candidates {
		// VETO checks
		// 1. Both UAA and MACs mismatch
		if normMAC != "" && c.MAC != "" && !IsLocallyAdministered(normMAC) && !IsLocallyAdministered(c.MAC) && normMAC != c.MAC {
			continue
		}
		// 2. Candidate is managed with active agent, but observation IP is not in agent interfaces
		if c.Managed && c.AgentAlive {
			ipInAgent := false
			for _, ifaceIP := range c.AgentInterfaces {
				if ifaceIP == o.IP {
					ipInAgent = true
					break
				}
			}
			if !ipInAgent {
				continue
			}
		}

		s := 0.0

		// Equal MAC (including matching random LAA MACs)
		if normMAC != "" && normMAC == c.MAC {
			s += m.weights.MAC
		}

		// IP lease check
		if o.IP == c.CurrentIP {
			if now.Sub(c.LastSeen) <= m.weights.LeaseWindow {
				s += m.weights.IPLease
			} else {
				s += m.weights.IPStale
			}
		}

		// Hostname evidence
		if normHost != "" && normHost == c.Hostname {
			s += m.weights.Hostname
		} else if normHost != "" && c.Hostname != "" && normHost != c.Hostname {
			s += m.weights.HostConflict
		}

		// Port profile Jaccard similarity
		if len(o.Ports) > 0 && len(c.Ports) > 0 {
			s += m.weights.Ports * Jaccard(o.Ports, c.Ports)
		}

		// Non-random OUI match
		if oui := OUI(normMAC); oui != "" && oui == OUI(c.MAC) {
			s += m.weights.OUI
		}

		scored = append(scored, scoredCandidate{c: c, score: s})
	}

	if len(scored) == 0 {
		return Decision{
			Action:     ActionCreateNew,
			Confidence: 0.3,
			Reason:     "no_candidates",
			Score:      0.0,
		}, nil
	}

	// Sort total order: (score DESC, last_seen DESC, id ASC)
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score > scored[j].score
		}
		if !scored[i].c.LastSeen.Equal(scored[j].c.LastSeen) {
			return scored[i].c.LastSeen.After(scored[j].c.LastSeen)
		}
		return scored[i].c.ID < scored[j].c.ID
	})

	top := scored[0]
	s1 := top.score
	s2 := 0.0
	var runnerUpID *int64
	if len(scored) > 1 {
		s2 = scored[1].score
		rID := scored[1].c.ID
		runnerUpID = &rID
	}

	if s1 >= m.weights.Threshold && (s1-s2) >= m.weights.Margin {
		conf := s1 / 100.0
		if conf > 1.0 {
			conf = 1.0
		}
		return Decision{
			Action:           ActionBind,
			DeviceID:         &top.c.ID,
			Confidence:       conf,
			Reason:           "weighted_match",
			Score:            s1,
			RunnerUpDeviceID: runnerUpID,
			RunnerUpScore:    s2,
		}, nil
	}

	topID := top.c.ID
	return Decision{
		Action:           ActionCreateNew,
		Confidence:       0.3,
		Reason:           "insufficient_evidence_or_margin",
		Score:            s1,
		RunnerUpDeviceID: &topID,
		RunnerUpScore:    s1,
	}, nil
}

