package detect

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Policy defines configurable allowlists and tuning parameters for rules R001–R010.
type Policy struct {
	ShellBinaries    []string `json:"shell_binaries"`
	NetworkDaemons   []string `json:"network_daemons"`
	DebuggerBinaries []string `json:"debugger_binaries"`
	SetuidBinaries   []string `json:"setuid_binaries"`
	SentinelIPs      []string `json:"sentinel_ips"`
	RulesetVersion   string   `json:"ruleset_version"`
}

// DefaultPolicy returns the hardened default detection policy per Architecture §2.2.
func DefaultPolicy() *Policy {
	return &Policy{
		ShellBinaries: []string{
			"sh", "bash", "dash", "zsh", "ash",
			"nc", "ncat", "socat",
			"python", "python3", "perl", "ruby", "php",
		},
		NetworkDaemons: []string{
			"nginx", "apache2", "httpd", "php-fpm", "java", "node",
		},
		DebuggerBinaries: []string{
			"gdb", "lldb", "rr", "criu",
		},
		SetuidBinaries: []string{
			"sudo", "su", "pkexec", "passwd", "newgrp", "login", "sshd",
		},
		SentinelIPs:    []string{"127.0.0.1", "::1"},
		RulesetVersion: "1.0.0",
	}
}

// LoadPolicy returns the active policy, loading overrides from CERBERUS_DETECT_POLICY if set.
func LoadPolicy() *Policy {
	policy := DefaultPolicy()
	if path := os.Getenv("CERBERUS_DETECT_POLICY"); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(data, policy)
		}
	}
	return policy
}

// IsShell returns true if the image or comm is a known command shell or scripting interpreter.
func (p *Policy) IsShell(image, comm string) bool {
	target := extractBase(image)
	if target == "" {
		target = extractBase(comm)
	}
	target = strings.ToLower(target)

	for _, s := range p.ShellBinaries {
		if target == s || strings.HasPrefix(target, s) {
			return true
		}
	}
	return false
}

// IsNetworkDaemon returns true if the process is a web/app server daemon (sshd-session excluded).
func (p *Policy) IsNetworkDaemon(image, comm string) bool {
	target := extractBase(image)
	if target == "" {
		target = extractBase(comm)
	}
	target = strings.ToLower(target)

	if target == "sshd-session" {
		return false
	}

	for _, d := range p.NetworkDaemons {
		if target == d || strings.HasPrefix(target, d) {
			return true
		}
	}
	return false
}

// IsDebugger returns true if comm is in the debugger allowlist {gdb, lldb, rr, criu}.
func (p *Policy) IsDebugger(comm string) bool {
	target := strings.ToLower(extractBase(comm))
	for _, dbg := range p.DebuggerBinaries {
		if target == dbg {
			return true
		}
	}
	return false
}

// IsSetuidAllowed returns true if the process is a recognized standard setuid utility.
func (p *Policy) IsSetuidAllowed(comm, image string) bool {
	target := extractBase(comm)
	if target == "" {
		target = extractBase(image)
	}
	target = strings.ToLower(target)

	for _, bin := range p.SetuidBinaries {
		if target == bin {
			return true
		}
	}
	return false
}

// IsExcludedConnectIP returns true if destination IP is loopback or sentinel IP.
func (p *Policy) IsExcludedConnectIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsLoopback() {
		return true
	}
	ipStr := ip.String()
	for _, s := range p.SentinelIPs {
		if ipStr == s {
			return true
		}
	}
	return false
}

func extractBase(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}
