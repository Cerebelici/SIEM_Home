package scanner

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/model"
)

// CommandRunner defines an interface for running external shell commands (enabling mocking).
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// DefaultCommandRunner executes commands via os/exec.
type DefaultCommandRunner struct{}

// Run executes the command with context and returns stdout.
func (r *DefaultCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	configureProcessGroup(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stdout.Bytes(), fmt.Errorf("command '%s %s' failed: %w (stderr: %s)",
			name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Scanner orchestrates Nmap discovery and vulnerability audits.
type Scanner struct {
	cfg    *config.Config
	runner CommandRunner
	caps   *model.Capabilities
}

// New creates a new Scanner instance with the default command runner.
func New(cfg *config.Config, caps ...*model.Capabilities) *Scanner {
	var c *model.Capabilities
	if len(caps) > 0 {
		c = caps[0]
	}
	return &Scanner{
		cfg:    cfg,
		runner: &DefaultCommandRunner{},
		caps:   c,
	}
}

// NewWithRunner creates a Scanner with a custom CommandRunner (for unit tests).
func NewWithRunner(cfg *config.Config, runner CommandRunner, caps ...*model.Capabilities) *Scanner {
	var c *model.Capabilities
	if len(caps) > 0 {
		c = caps[0]
	}
	return &Scanner{
		cfg:    cfg,
		runner: runner,
		caps:   c,
	}
}

// SetCapabilities updates the capability profile for the scanner.
func (s *Scanner) SetCapabilities(caps *model.Capabilities) {
	s.caps = caps
}

// Capabilities returns the active capability profile.
func (s *Scanner) Capabilities() *model.Capabilities {
	return s.caps
}

func (s *Scanner) isUnprivileged() bool {
	if s.caps != nil {
		return s.caps.EffectiveMode == "unprivileged"
	}
	if s.cfg != nil {
		return s.cfg.ForceUnprivileged
	}
	return true
}

func isCompleteNmapOutput(output []byte) bool {
	return bytes.Contains(output, []byte("<runstats>")) && bytes.Contains(output, []byte("exit=\"success\""))
}

// RunDiscoveryScan executes an Nmap host discovery scan against target CIDR.
func (s *Scanner) RunDiscoveryScan(ctx context.Context, target string) ([]model.Device, error) {
	if strings.HasPrefix(target, "-") {
		return nil, fmt.Errorf("invalid discovery target %q: target must not begin with '-'", target)
	}
	if _, err := netip.ParsePrefix(target); err != nil {
		if _, err := netip.ParseAddr(target); err != nil {
			return nil, fmt.Errorf("invalid discovery target %q: must be a valid CIDR prefix or IP address", target)
		}
	}

	args := []string{
		"-sn",
		"-n",
		"-T4",
		"--max-retries", "2",
		"--host-timeout", "10m",
		"-oX", "-",
	}

	if s.isUnprivileged() {
		args = append(args, "-PS22,80,135,139,443,445,3389,8080", "-PA80,443")
	}

	args = append(args, target)

	output, err := s.runner.Run(ctx, s.cfg.NmapPath, args...)
	if err != nil && !isCompleteNmapOutput(output) {
		return nil, fmt.Errorf("discovery scan failed: %w", err)
	}

	run, parseErr := ParseNmapXML(output)
	if parseErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("failed to parse discovery xml: %w", parseErr)
	}

	devices := ExtractDevices(run)
	return devices, nil
}

// RunVulnerabilityScan executes service detection and vulnerability scripts against target IPs.
func (s *Scanner) RunVulnerabilityScan(ctx context.Context, targets []string) ([]model.ScanHostResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	for _, target := range targets {
		if strings.HasPrefix(target, "-") {
			return nil, fmt.Errorf("invalid scan target %q: target must not begin with '-'", target)
		}
		if _, err := netip.ParseAddr(target); err != nil {
			if _, err := netip.ParsePrefix(target); err != nil {
				return nil, fmt.Errorf("invalid scan target %q: must be a valid IP address or CIDR prefix", target)
			}
		}
	}

	vulnScript := s.cfg.VulnScript
	if vulnScript == "" {
		vulnScript = "vulners"
	}

	args := []string{
		"-sV",
		"--version-intensity", "5",
		"-T4",
		"--max-retries", "2",
		"--host-timeout", "10m",
		"--script", vulnScript,
		"-n",
		"-oX", "-",
	}

	if s.isUnprivileged() {
		args = append(args, "-sT", "-Pn")
	}

	args = append(args, targets...)

	output, err := s.runner.Run(ctx, s.cfg.NmapPath, args...)
	if err != nil && !isCompleteNmapOutput(output) {
		return nil, fmt.Errorf("vulnerability scan failed: %w", err)
	}

	run, parseErr := ParseNmapXML(output)
	if parseErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("failed to parse vulnerability xml: %w", parseErr)
	}

	results := ExtractHostResults(run)
	return results, nil
}
