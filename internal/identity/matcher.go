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
	IP           string
	MAC          string
	Hostname     string
	Vendor       string
	Ports        []string
	Fingerprints []string
	ObservedAt   time.Time
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
	Fingerprints       []string
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
	LAAMACMove      float64
	IPLease         float64
	IPOnlyLease     float64
	IPStale         float64
	Hostname        float64
	Ports           float64
	HostPortSynergy float64
	OUI             float64
	HostConflict    float64
	Threshold       float64
	Margin          float64
	LeaseWindow     time.Duration
	CandidateWindow time.Duration
}

// DefaultWeights returns standard matcher tuning across the 3-Tier identification hierarchy.
func DefaultWeights() Weights {
	return Weights{
		MAC:             40,
		LAAMACMove:      15,
		IPLease:         30,
		IPOnlyLease:     20,
		IPStale:         10,
		Hostname:        25,
		Ports:           20,
		HostPortSynergy: 10,
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

// isEmptyStub reports a device at ip that carries no identity evidence at all: no MAC,
// hostname, services, fingerprints or agent. Unprivileged sweeps create such records.
func isEmptyStub(c Candidate, ip string) bool {
	return c.CurrentIP == ip && c.MAC == "" && c.Hostname == "" && len(c.Ports) == 0 &&
		len(c.Fingerprints) == 0 && !c.Managed
}

func isProvisionalDiscoveryStub(c Candidate, obsIP string) bool {
	return c.CurrentIP == obsIP &&
		!c.Managed &&
		c.IdentityConfidence > 0 &&
		c.IdentityConfidence <= 0.35 &&
		len(c.Ports) == 0 &&
		len(c.Fingerprints) == 0
}

// Resolve evaluates an observation against candidate devices using the 3-Tier reconciliation algorithm:
//   - Tier 1: Cryptographic & Cooperative Identity (Managed agent interface/MAC or SSH/TLS/UUID fingerprint)
//   - Tier 2: Hardware UAA MAC & Per-Wi-Fi Persistent Randomized (LAA) MAC
//   - Tier 3: Deferred Hostname + Port Profile Reconciliation (post-vulnerability scan)
func (m *Matcher) Resolve(ctx context.Context, o Observation) (Decision, error) {
	now := o.ObservedAt
	if now.IsZero() {
		now = m.clock()
	}

	normMAC := NormalizeMAC(o.MAC)
	normHost := NormalizeHostname(o.Hostname)
	normFPs := NormalizeFingerprints(o.Fingerprints)

	candidates, err := m.store.GetCandidates(ctx, m.weights.CandidateWindow)
	if err != nil {
		return Decision{}, err
	}

	// A device with identity evidence that holds o.IP within its lease outranks empty stubs at
	// the same IP: those are earlier sightings of the same host without a MAC. Letting them
	// compete makes every match ambiguous and creates one more duplicate per scan. Binding
	// merges them into the device (see storage ApplyDecision).
	richHolderAtIP := false
	for _, c := range candidates {
		if c.CurrentIP == o.IP && !isEmptyStub(c, o.IP) && now.Sub(c.LastSeen) <= m.weights.LeaseWindow {
			richHolderAtIP = true
			break
		}
	}

	// Tier 1a — Managed Agent Binding (deterministic, wins outright)
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
			// Also match if the agent's hardware/interface MAC matches directly during a DHCP IP transition
			exactAgentMAC := (normMAC != "" && c.MAC != "" && normMAC == c.MAC)
			if (containsIP && macMatches) || exactAgentMAC {
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

	// Tier 1b — Cryptographic & Service Fingerprints (SSH host key, TLS cert, SMB/UPnP UUID)
	if len(normFPs) > 0 {
		var fpMatches []Candidate
		for _, c := range candidates {
			// Veto if both have globally unique hardware MACs that disagree
			if normMAC != "" && c.MAC != "" && !IsLocallyAdministered(normMAC) && !IsLocallyAdministered(c.MAC) && normMAC != c.MAC {
				continue
			}
			if HasSharedFingerprint(normFPs, c.Fingerprints) {
				fpMatches = append(fpMatches, c)
			}
		}
		if len(fpMatches) >= 1 {
			sort.SliceStable(fpMatches, func(i, j int) bool {
				if !fpMatches[i].LastSeen.Equal(fpMatches[j].LastSeen) {
					return fpMatches[i].LastSeen.After(fpMatches[j].LastSeen)
				}
				return fpMatches[i].ID < fpMatches[j].ID
			})
			devID := fpMatches[0].ID
			return Decision{
				Action:     ActionBind,
				DeviceID:   &devID,
				Confidence: 1.0,
				Reason:     "crypto_fingerprint",
				Score:      100.0,
			}, nil
		}
	}

	// Tier 2a — Globally Unique Hardware MAC (UAA)
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

	// Tier 2b & Tier 3 — Per-Wi-Fi Randomized MAC & Enriched Post-Scan Evidence
	scoreCandidates := func(skipProvisionalStub bool) []scoredCandidate {
		var list []scoredCandidate
		for _, c := range candidates {
			if skipProvisionalStub && isProvisionalDiscoveryStub(c, o.IP) {
				continue
			}
			if richHolderAtIP && isEmptyStub(c, o.IP) {
				continue
			}

			// VETO checks
			// 1. Both UAA and MACs mismatch
			if normMAC != "" && c.MAC != "" && !IsLocallyAdministered(normMAC) && !IsLocallyAdministered(c.MAC) && normMAC != c.MAC {
				continue
			}
			// 2. Candidate is managed with active agent, but observation neither matches agent IP nor MAC
			if c.Managed && c.AgentAlive {
				ipInAgent := false
				for _, ifaceIP := range c.AgentInterfaces {
					if ifaceIP == o.IP {
						ipInAgent = true
						break
					}
				}
				macMatchesAgent := (normMAC != "" && c.MAC != "" && normMAC == c.MAC)
				if !ipInAgent && !macMatchesAgent {
					continue
				}
			}
			// 3. Both have cryptographic fingerprints, and none match
			if len(normFPs) > 0 && len(c.Fingerprints) > 0 && !HasSharedFingerprint(normFPs, c.Fingerprints) {
				continue
			}

			s := 0.0

			// Hostname evidence
			hostMatched := false
			hostConflicted := false
			if normHost != "" && normHost == c.Hostname {
				s += m.weights.Hostname
				hostMatched = true
			} else if normHost != "" && c.Hostname != "" && normHost != c.Hostname {
				s += m.weights.HostConflict
				hostConflicted = true
			}

			// Equal MAC (including Per-SSID persistent randomized LAA MACs)
			if normMAC != "" && normMAC == c.MAC {
				s += m.weights.MAC
				// Tier 2b: Modern OSes reuse the same randomized MAC per Wi-Fi SSID.
				// When the router assigns a new DHCP IP (or the prior lease expired),
				// add LAAMACMove so an exact MAC match clears the threshold unless conflicted.
				if o.IP != c.CurrentIP || now.Sub(c.LastSeen) > m.weights.LeaseWindow {
					s += m.weights.LAAMACMove
				}
			}

			// IP lease check
			if o.IP == c.CurrentIP {
				if now.Sub(c.LastSeen) <= m.weights.LeaseWindow {
					s += m.weights.IPLease
					// When one side has no MAC (an unprivileged TCP scan cannot read it, or the
					// device was first recorded without it), MACs cannot confirm or refute the
					// match. An active IP within its lease and no hostname conflict is then the
					// best evidence: award IPOnlyLease so it binds instead of duplicating.
					if (normMAC == "" || c.MAC == "") && !hostConflicted {
						s += m.weights.IPOnlyLease
					}
				} else {
					s += m.weights.IPStale
				}
			}

			// Port profile Jaccard similarity
			if len(o.Ports) > 0 && len(c.Ports) > 0 {
				jaccard := Jaccard(o.Ports, c.Ports)
				s += m.weights.Ports * jaccard
				// Tier 3: Deferred Hostname + Port Profile Synergy when a device changes both IP and MAC
				if hostMatched && jaccard >= 0.5 {
					s += m.weights.HostPortSynergy
				}
			}

			// Non-random OUI match
			if oui := OUI(normMAC); oui != "" && oui == OUI(c.MAC) {
				s += m.weights.OUI
			}

			list = append(list, scoredCandidate{c: c, score: s})
		}

		sort.SliceStable(list, func(i, j int) bool {
			if list[i].score != list[j].score {
				return list[i].score > list[j].score
			}
			if !list[i].c.LastSeen.Equal(list[j].c.LastSeen) {
				return list[i].c.LastSeen.After(list[j].c.LastSeen)
			}
			return list[i].c.ID < list[j].c.ID
		})
		return list
	}

	// Tier 3 Deferred Check: If this observation carries post-scan service ports, first check if an
	// existing historical device (at a previous IP) matches above threshold before falling back to
	// any unverified provisional stub created during the -sn discovery sweep.
	if len(o.Ports) > 0 {
		nonStubScored := scoreCandidates(true)
		if len(nonStubScored) > 0 && nonStubScored[0].c.CurrentIP != o.IP {
			top := nonStubScored[0]
			s1 := top.score
			s2 := 0.0
			var runnerUpID *int64
			if len(nonStubScored) > 1 {
				s2 = nonStubScored[1].score
				rID := nonStubScored[1].c.ID
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
					Reason:           "deferred_service_match",
					Score:            s1,
					RunnerUpDeviceID: runnerUpID,
					RunnerUpScore:    s2,
				}, nil
			}
		}
	}

	scored := scoreCandidates(false)
	if len(scored) == 0 {
		return Decision{
			Action:     ActionCreateNew,
			Confidence: 0.3,
			Reason:     "no_candidates",
			Score:      0.0,
		}, nil
	}

	// If this is a bare IP-only observation (no MAC, no hostname, no ports) and multiple identical
	// duplicate rows already exist at o.IP, collapse runner-up duplicates of the same empty IP
	// so the most recent record at o.IP can bind cleanly without failing the margin check.
	if normMAC == "" && normHost == "" && len(o.Ports) == 0 && len(normFPs) == 0 && len(scored) > 1 {
		var deduped []scoredCandidate
		seenEmptyIP := false
		for _, sc := range scored {
			if sc.c.CurrentIP == o.IP && sc.c.MAC == "" && sc.c.Hostname == "" && len(sc.c.Ports) == 0 {
				if seenEmptyIP {
					continue
				}
				seenEmptyIP = true
			}
			deduped = append(deduped, sc)
		}
		scored = deduped
	}

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
