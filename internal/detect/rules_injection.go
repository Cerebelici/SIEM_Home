package detect

import (
	"strings"

	"github.com/gr0gu/cerberus/internal/model"
)

// RuleR003 detects cross-process memory injection via process_vm_writev.
type RuleR003 struct{}

func (r *RuleR003) ID() string { return "CRB-R003" }

func (r *RuleR003) Evaluate(ev *model.NormalizedEvent, st *HostState, policy *Policy) []Finding {
	if ev.Type != "PROC_INJECTION" {
		return nil
	}

	method := strings.ToLower(ev.Action)
	if method != "process_vm_writev" {
		return nil
	}

	// Ignore self-target or unassigned target
	if ev.TargetPID == 0 || ev.TargetPID == ev.PID {
		return nil
	}

	severity := "CRITICAL"
	score := 9.5
	if policy.IsDebugger(ev.Comm) {
		severity = "HIGH"
		score = 7.5
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
			Title:          "Process memory injection via process_vm_writev",
			Severity:       severity,
			Score:          score,
			MitreTactic:    "Defense Evasion",
			MitreTechnique: "T1055.009",
			PIDRoot:        pidRoot,
			Evidence:       evidence,
		},
	}
}

// RuleR004 detects ptrace execution / memory tampering by non-debugger processes.
type RuleR004 struct{}

func (r *RuleR004) ID() string { return "CRB-R004" }

func (r *RuleR004) Evaluate(ev *model.NormalizedEvent, st *HostState, policy *Policy) []Finding {
	if ev.Type != "PROC_INJECTION" {
		return nil
	}

	method := strings.ToLower(ev.Action)
	if method != "ptrace" {
		return nil
	}

	// Ignore self-target
	if ev.TargetPID == 0 || ev.TargetPID == ev.PID {
		return nil
	}

	// Ignore authorized debuggers
	if policy.IsDebugger(ev.Comm) {
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
			Title:          "Suspicious ptrace process injection",
			Severity:       "HIGH",
			Score:          8.0,
			MitreTactic:    "Defense Evasion",
			MitreTechnique: "T1055.008",
			PIDRoot:        pidRoot,
			Evidence:       evidence,
		},
	}
}
