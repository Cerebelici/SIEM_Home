package posture

import (
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

func TestScore_GoldenVector(t *testing.T) {
	p := DefaultPolicy

	// Host A: CVEs 9.8, 7.5, 5.3
	scoresA := []float64{9.8, 7.5, 5.3}
	riskA := HostRisk(scoresA, p)
	if math.Abs(riskA-9.869) > 1e-3 {
		t.Errorf("Host A expected risk ~9.869, got %.5f", riskA)
	}

	// Host B: CVEs 5.0, 5.0, 5.0, 5.0
	scoresB := []float64{5.0, 5.0, 5.0, 5.0}
	riskB := HostRisk(scoresB, p)
	if math.Abs(riskB-6.445) > 1e-3 {
		t.Errorf("Host B expected risk ~6.445, got %.5f", riskB)
	}

	// Host C: no CVEs
	var scoresC []float64
	riskC := HostRisk(scoresC, p)
	if riskC != 0.0 {
		t.Errorf("Host C expected risk 0.0, got %.5f", riskC)
	}

	// Fleet score without incidents
	risks := []float64{riskA, riskB, riskC}
	fScore, reason := FleetScore(risks, 0, p)
	if reason != "" || fScore == nil {
		t.Fatalf("unexpected fleet error: reason=%s, fScore=%v", reason, fScore)
	}
	if *fScore != 27.9 {
		t.Errorf("expected fleet score 27.9, got %.2f", *fScore)
	}

	// 1 HIGH incident on A (penalty = 8)
	incidentCounts := map[string]int{"HIGH": 1}
	penalty := IncidentPenalty(incidentCounts, p)
	if penalty != 8.0 {
		t.Fatalf("expected penalty 8.0, got %.2f", penalty)
	}

	fScoreWithIncident, _ := FleetScore(risks, penalty, p)
	if fScoreWithIncident == nil || *fScoreWithIncident != 19.9 {
		t.Errorf("expected fleet score with incident 19.9, got %v", fScoreWithIncident)
	}
}

func TestScore_Properties(t *testing.T) {
	p := DefaultPolicy
	r := rand.New(rand.NewSource(42))

	for i := 0; i < 10000; i++ {
		n := r.Intn(10) // 0 to 9 scores
		scores := make([]float64, n)
		var maxS float64
		for j := 0; j < n; j++ {
			scores[j] = r.Float64() * 10.0
			if scores[j] > maxS {
				maxS = scores[j]
			}
		}

		risk := HostRisk(scores, p)

		// 1. 0 <= R <= 10
		if risk < 0.0 || risk > 10.0 {
			t.Fatalf("iteration %d: risk %.5f out of bounds [0, 10]", i, risk)
		}

		// 2. R >= max(s)
		if n > 0 && risk < maxS-1e-9 {
			t.Fatalf("iteration %d: risk %.5f < max score %.5f", i, risk, maxS)
		}

		// 3. Adding a CVE never decreases R (Monotone)
		newScore := r.Float64() * 10.0
		extendedScores := append([]float64{newScore}, scores...)
		extendedRisk := HostRisk(extendedScores, p)
		if extendedRisk < risk-1e-9 {
			t.Fatalf("iteration %d: adding score %.2f decreased risk from %.5f to %.5f", i, newScore, risk, extendedRisk)
		}

		// 4. Permutation invariant
		shuffled := make([]float64, n)
		copy(shuffled, scores)
		r.Shuffle(len(shuffled), func(a, b int) {
			shuffled[a], shuffled[b] = shuffled[b], shuffled[a]
		})
		shuffledRisk := HostRisk(shuffled, p)
		if math.Abs(risk-shuffledRisk) > 1e-12 {
			t.Fatalf("iteration %d: permutation produced different risk: %.12f vs %.12f", i, risk, shuffledRisk)
		}
	}
}

func TestScore_EdgeCases(t *testing.T) {
	p := DefaultPolicy

	// Empty fleet
	fEmpty, reason := FleetScore(nil, 0, p)
	if fEmpty != nil || reason != "no_assets" {
		t.Errorf("expected nil, 'no_assets', got %v, %s", fEmpty, reason)
	}

	// Unknown CVSS (CVSS <= 0)
	effUnknown := EffectiveScore(0, false, p)
	if effUnknown != 4.0 {
		t.Errorf("expected 4.0 for unknown CVSS, got %.2f", effUnknown)
	}

	effNegative := EffectiveScore(-1.5, false, p)
	if effNegative != 4.0 {
		t.Errorf("expected 4.0 for negative CVSS, got %.2f", effNegative)
	}

	// is_exploit multiplier with 9.0 capped at 10.0
	effExploit := EffectiveScore(9.0, true, p)
	if effExploit != 10.0 {
		t.Errorf("expected 10.0 capped for 9.0 * 1.2, got %.2f", effExploit)
	}

	// HostScore bounds
	if HostScore(0.0) != 100.0 {
		t.Errorf("expected HostScore(0) = 100, got %.2f", HostScore(0.0))
	}
	if HostScore(10.0) != 0.0 {
		t.Errorf("expected HostScore(10) = 0, got %.2f", HostScore(10.0))
	}

	// Incident penalty cap
	largeIncidentCounts := map[string]int{
		"CRITICAL": 5, // 5 * 15 = 75
		"HIGH":     5, // 5 * 8 = 40
	}
	pen := IncidentPenalty(largeIncidentCounts, p)
	if pen != p.PenaltyCap {
		t.Errorf("expected penalty capped at %.1f, got %.1f", p.PenaltyCap, pen)
	}
}

func TestScore_DeduplicationAndResolved(t *testing.T) {
	p := DefaultPolicy
	now := time.Now().UTC()

	vulns := []model.Vulnerability{
		{
			CVEID:       "CVE-2023-1111",
			CVSSScore:   6.0,
			ServicePort: 80,
			Status:      "open",
			LastSeenAt:  now,
		},
		{
			CVEID:       "CVE-2023-1111",
			CVSSScore:   8.5, // Same CVE on different port with higher score
			ServicePort: 443,
			Status:      "open",
			LastSeenAt:  now,
		},
		{
			CVEID:       "CVE-2023-2222",
			CVSSScore:   9.0,
			ServicePort: 22,
			Status:      "resolved", // Should be ignored
			LastSeenAt:  now,
		},
	}

	scores := DeduplicateDeviceCVEs(vulns, p)
	if len(scores) != 1 {
		t.Fatalf("expected 1 deduplicated score, got %d", len(scores))
	}
	if scores[0] != 8.5 {
		t.Errorf("expected max score 8.5, got %.2f", scores[0])
	}
}

func TestScore_BitIdentical(t *testing.T) {
	p := DefaultPolicy
	scores := []float64{9.8, 7.5, 5.3}

	r1 := HostRisk(scores, p)
	r2 := HostRisk(scores, p)
	if math.Float64bits(r1) != math.Float64bits(r2) {
		t.Errorf("expected bit-identical float64 outputs: %x != %x", math.Float64bits(r1), math.Float64bits(r2))
	}
}
