package detect

import (
	"regexp"
	"strings"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

var (
	reR002Patterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)/dev/tcp/`),
		regexp.MustCompile(`(?i)bash\s+-i\s+>&`),
		regexp.MustCompile(`(?i)nc\s+-[a-zA-Z]*e`),
		regexp.MustCompile(`(?i)mkfifo.+nc\s+`),
		regexp.MustCompile(`(?i)socat\s+.*exec:`),
	}
)

// RuleR001 detects correlated reverse shell network connections from shells or scripts.
type RuleR001 struct{}

func (r *RuleR001) ID() string { return "CRB-R001" }

func (r *RuleR001) Evaluate(ev *model.NormalizedEvent, st *HostState, policy *Policy) []Finding {
	if ev.Type != "CONNECT" {
		return nil
	}

	// 1. Exclude loopback, sentinel IPs, and DNS port 53
	if policy.IsExcludedConnectIP(ev.DstIP) || ev.DstPort == 53 {
		return nil
	}

	// 2. Process image must be a shell / script interpreter
	proc := st.GetProc(ev.PID, ev.TS)
	procImage := ev.Image
	if proc != nil && proc.Image != "" {
		procImage = proc.Image
	}

	if !policy.IsShell(procImage, ev.Comm) {
		return nil
	}

	// 3. Correlated condition: EXEC in the last 30s OR parent is a network daemon
	isRecentExec := false
	if proc != nil && !proc.ExecTS.IsZero() {
		diff := ev.TS.Sub(proc.ExecTS)
		if diff >= 0 && diff <= 30*time.Second {
			isRecentExec = true
		}
	}

	isParentDaemon := false
	ppid := ev.PPID
	if proc != nil && proc.PPID > 0 {
		ppid = proc.PPID
	}
	if ppid > 0 {
		parent := st.GetProc(ppid, ev.TS)
		if parent != nil && policy.IsNetworkDaemon(parent.Image, parent.Comm) {
			isParentDaemon = true
		}
	}

	if !isRecentExec && !isParentDaemon {
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
			Title:          "Correlated reverse shell connection",
			Severity:       "CRITICAL",
			Score:          9.5,
			MitreTactic:    "TA0011",
			MitreTechnique: "T1059.004",
			PIDRoot:        pidRoot,
			Evidence:       evidence,
		},
	}
}

// RuleR002 detects interactive reverse-shell command syntax in bash readline input.
type RuleR002 struct{}

func (r *RuleR002) ID() string { return "CRB-R002" }

func (r *RuleR002) Evaluate(ev *model.NormalizedEvent, st *HostState, policy *Policy) []Finding {
	if ev.Type != "BASH_READLINE" {
		return nil
	}

	cmd := strings.TrimSpace(ev.Command)
	if cmd == "" {
		return nil
	}

	matched := false
	for _, re := range reR002Patterns {
		if re.MatchString(cmd) {
			matched = true
			break
		}
	}

	if !matched {
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
			Title:          "Interactive reverse shell command executed",
			Severity:       "CRITICAL",
			Score:          9.0,
			MitreTactic:    "Execution",
			MitreTechnique: "T1059.004",
			PIDRoot:        pidRoot,
			Evidence:       evidence,
		},
	}
}

// RuleR005 detects web server processes spawning interactive shells (webshell activity).
type RuleR005 struct{}

func (r *RuleR005) ID() string { return "CRB-R005" }

func (r *RuleR005) Evaluate(ev *model.NormalizedEvent, st *HostState, policy *Policy) []Finding {
	if ev.Type != "EXEC" {
		return nil
	}

	if !policy.IsShell(ev.Image, ev.Comm) {
		return nil
	}

	if ev.PPID <= 0 {
		return nil
	}

	parent := st.GetProc(ev.PPID, ev.TS)
	if parent == nil || !policy.IsNetworkDaemon(parent.Image, parent.Comm) {
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
			Title:          "Web application spawned interactive shell",
			Severity:       "HIGH",
			Score:          8.0,
			MitreTactic:    "Persistence",
			MitreTechnique: "T1505.003",
			PIDRoot:        pidRoot,
			Evidence:       evidence,
		},
	}
}
