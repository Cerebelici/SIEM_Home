package detect

import (
	"strings"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

// RuleR006 detects fileless binary execution via memfd_create within 10 seconds.
type RuleR006 struct{}

func (r *RuleR006) ID() string { return "CRB-R006" }

func (r *RuleR006) Evaluate(ev *model.NormalizedEvent, st *HostState, policy *Policy) []Finding {
	if ev.Type != "EXEC" {
		return nil
	}

	image := ev.Image
	isMemfdImage := strings.HasPrefix(image, "/proc/self/fd/") ||
		strings.HasPrefix(image, "memfd:") ||
		(strings.HasPrefix(image, "/proc/") && strings.Contains(image, "/fd/"))

	if !isMemfdImage {
		return nil
	}

	proc := st.GetProc(ev.PID, ev.TS)
	if proc == nil || proc.MemfdTS.IsZero() {
		return nil
	}

	diff := ev.TS.Sub(proc.MemfdTS)
	if diff < 0 || diff > 10*time.Second {
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
			Title:          "Fileless binary execution from memory descriptor",
			Severity:       "CRITICAL",
			Score:          9.5,
			MitreTactic:    "Defense Evasion",
			MitreTechnique: "T1620",
			PIDRoot:        pidRoot,
			Evidence:       evidence,
		},
	}
}

// RuleR007 detects unauthorized tampering with sensitive system and security configuration files.
type RuleR007 struct{}

func (r *RuleR007) ID() string { return "CRB-R007" }

func (r *RuleR007) Evaluate(ev *model.NormalizedEvent, st *HostState, policy *Policy) []Finding {
	if ev.Type != "FILE_TAMPER" {
		return nil
	}

	path := ev.Path
	var (
		severity  string
		score     float64
		technique string
	)

	if path == "/etc/shadow" || path == "/etc/ld.so.preload" {
		severity = "CRITICAL"
		score = 9.5
		if path == "/etc/shadow" {
			technique = "T1003.008"
		} else {
			technique = "T1574.006"
		}
	} else if strings.HasPrefix(path, "/etc/sudoers") || strings.HasPrefix(path, "/etc/cron") || strings.Contains(path, "authorized_keys") {
		severity = "HIGH"
		score = 7.5
		technique = "T1098.004"
	} else {
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
			Title:          "Tampering with sensitive security file",
			Severity:       severity,
			Score:          score,
			MitreTactic:    "Persistence",
			MitreTechnique: technique,
			PIDRoot:        pidRoot,
			Evidence:       evidence,
		},
	}
}

// RuleR008 detects privilege escalation to UID 0 by binaries outside standard setuid tools.
type RuleR008 struct{}

func (r *RuleR008) ID() string { return "CRB-R008" }

func (r *RuleR008) Evaluate(ev *model.NormalizedEvent, st *HostState, policy *Policy) []Finding {
	if ev.Type != "PRIV_ESC" {
		return nil
	}

	if ev.TargetUID != 0 || ev.OldUID == 0 {
		return nil
	}

	if policy.IsSetuidAllowed(ev.Comm, ev.Image) {
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
			Title:          "Unauthorized privilege escalation to root",
			Severity:       "HIGH",
			Score:          8.5,
			MitreTactic:    "Privilege Escalation",
			MitreTechnique: "T1068",
			PIDRoot:        pidRoot,
			Evidence:       evidence,
		},
	}
}

// RuleR009 detects kernel module load operations, escalating if paths point to volatile directories.
type RuleR009 struct{}

func (r *RuleR009) ID() string { return "CRB-R009" }

func (r *RuleR009) Evaluate(ev *model.NormalizedEvent, st *HostState, policy *Policy) []Finding {
	if ev.Type != "KERNEL_MODULE" {
		return nil
	}

	combined := ev.Path + " " + ev.Command
	severity := "HIGH"
	score := 7.5

	if strings.Contains(combined, "/tmp") || strings.Contains(combined, "/dev/shm") || strings.Contains(combined, "/var/tmp") {
		severity = "CRITICAL"
		score = 9.5
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
			Title:          "Kernel module loaded",
			Severity:       severity,
			Score:          score,
			MitreTactic:    "Persistence",
			MitreTechnique: "T1547.006",
			PIDRoot:        pidRoot,
			Evidence:       evidence,
		},
	}
}
