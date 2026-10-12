package posture

import (
	"math"
	"sort"
	"strings"

	"github.com/gr0gu/cerberus/internal/model"
)

// Round1 rounds a float64 to 1 decimal place.
func Round1(x float64) float64 {
	return math.Round(x*10) / 10
}

// EffectiveScore computes the effective risk score for a single CVE finding.
// s_i = min(10, c_i * m_i)
// c_i = cvss if cvss > 0 else p.UnknownCVSS (default 4.0)
// m_i = p.ExploitMultiplier (default 1.2) if isExploit else 1.0
func EffectiveScore(cvss float64, isExploit bool, p Policy) float64 {
	c := cvss
	if c <= 0 {
		c = p.UnknownCVSS
	}
	m := 1.0
	if isExploit {
		m = p.ExploitMultiplier
	}
	s := c * m
	if s > 10.0 {
		s = 10.0
	}
	return s
}

// DeduplicateDeviceCVEs aggregates vulnerabilities per host, deduplicating by CVE ID
// and keeping the maximum effective score across affected ports/services.
func DeduplicateDeviceCVEs(vulns []model.Vulnerability, p Policy) []float64 {
	if len(vulns) == 0 {
		return nil
	}

	cveMax := make(map[string]float64)
	var anonScores []float64

	for _, v := range vulns {
		if v.Status == "resolved" {
			continue
		}
		eff := EffectiveScore(v.CVSSScore, v.IsExploit, p)
		cveID := strings.TrimSpace(v.CVEID)
		if cveID != "" {
			if existing, ok := cveMax[cveID]; !ok || eff > existing {
				cveMax[cveID] = eff
			}
		} else {
			anonScores = append(anonScores, eff)
		}
	}

	scores := make([]float64, 0, len(cveMax)+len(anonScores))
	for _, eff := range cveMax {
		scores = append(scores, eff)
	}
	scores = append(scores, anonScores...)
	return scores
}

// HostRisk computes the host risk R_h in [0, 10] using the deterministic formula:
// Sort s_(1) >= s_(2) >= ...
// R_h = s_(1) + (10 - s_(1)) * gamma * [1 - \prod_{i >= 2} (1 - (s_(i)/10)^2)]
func HostRisk(scores []float64, p Policy) float64 {
	if len(scores) == 0 {
		return 0.0
	}

	sorted := make([]float64, len(scores))
	copy(sorted, scores)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] > sorted[j]
	})

	s1 := sorted[0]
	if len(sorted) == 1 {
		return s1
	}

	prod := 1.0
	for _, s := range sorted[1:] {
		norm := s / 10.0
		prod *= (1.0 - norm*norm)
	}

	risk := s1 + (10.0-s1)*p.Gamma*(1.0-prod)
	if risk > 10.0 {
		risk = 10.0
	}
	if risk < 0.0 {
		risk = 0.0
	}
	return risk
}

// HostScore maps host risk R_h in [0, 10] to host health H_h in [0, 100].
// H_h = 100 * (1 - R_h / 10)
func HostScore(risk float64) float64 {
	score := 100.0 * (1.0 - risk/10.0)
	if score < 0.0 {
		score = 0.0
	}
	if score > 100.0 {
		score = 100.0
	}
	return score
}

// IncidentPenalty computes the total fleet penalty P from incident counts by severity.
// P = min(p.PenaltyCap, \sum points[sev] * count[sev])
func IncidentPenalty(counts map[string]int, p Policy) float64 {
	var total float64
	for sev, count := range counts {
		if count <= 0 {
			continue
		}
		pts := p.IncidentPoints[strings.ToUpper(sev)]
		total += pts * float64(count)
	}
	if total > p.PenaltyCap {
		total = p.PenaltyCap
	}
	return total
}

// FleetScore computes the network fleet score F over active devices D:
// blend = lambda * max(R_h) + (1 - lambda) * mean(R_h)
// F = clamp_[0, 100](100 - 10 * blend - penalty)
// Returns nil, "no_assets" if len(risks) == 0.
func FleetScore(risks []float64, penalty float64, p Policy) (*float64, string) {
	if len(risks) == 0 {
		return nil, "no_assets"
	}

	maxR := 0.0
	sumR := 0.0
	for _, r := range risks {
		if r > maxR {
			maxR = r
		}
		sumR += r
	}
	meanR := sumR / float64(len(risks))

	blend := p.Lambda*maxR + (1.0-p.Lambda)*meanR
	raw := 100.0 - 10.0*blend - penalty
	if raw < 0.0 {
		raw = 0.0
	}
	if raw > 100.0 {
		raw = 100.0
	}

	rounded := Round1(raw)
	return &rounded, ""
}
