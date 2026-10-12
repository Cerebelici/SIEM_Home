package detect

import "github.com/gr0gu/cerberus/internal/model"

// RuleR010 detects rapid outbound network fan-out (>= 50 distinct destinations within 10s).
type RuleR010 struct{}

func (r *RuleR010) ID() string { return "CRB-R010" }

func (r *RuleR010) Evaluate(ev *model.NormalizedEvent, st *HostState, policy *Policy) []Finding {
	if ev.Type != "CONNECT" {
		return nil
	}

	proc := st.GetProc(ev.PID, ev.TS)
	if proc == nil {
		return nil
	}

	if proc.OutboundFanoutCount(ev.TS) < 50 {
		return nil
	}

	pidRoot := st.ResolvePIDRoot(ev.PID, ev.TS, policy)
	var evidence []int64
	if ev.ID > 0 {
		evidence = []int64{ev.ID}
	}

	return []Finding{
		{
			RuleID:         r.ID(),
			RulesetVersion: policy.RulesetVersion,
			Title:          "High-frequency outbound network fan-out",
			Severity:       "MEDIUM",
			Score:          5.0,
			MitreTactic:    "Discovery",
			MitreTechnique: "T1046",
			PIDRoot:        pidRoot,
			Evidence:       evidence,
		},
	}
}
