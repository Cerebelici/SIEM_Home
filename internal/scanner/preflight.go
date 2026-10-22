package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/model"
)

var (
	ErrNmapNotFound = errors.New("nmap binary not found")
	versionRegex    = regexp.MustCompile(`Nmap version (\d+)\.(\d+)`)
)

// Preflight probes the local system environment to build a capability profile.
func Preflight(ctx context.Context, cfg *config.Config, r CommandRunner, look func(string) (string, error)) (*model.Capabilities, error) {
	if look == nil {
		return nil, errors.New("look function must not be nil")
	}
	if r == nil {
		r = &DefaultCommandRunner{}
	}

	nmapPath := cfg.NmapPath
	if nmapPath == "" {
		nmapPath = "nmap"
	}

	resolvedPath, err := look(nmapPath)
	if err != nil {
		fallback := ResolveNmapBinary(nmapPath)
		if fallback != "" && fallback != nmapPath {
			resolvedPath, err = look(fallback)
		}
	}
	if err != nil {
		return nil, ErrNmapNotFound
	}

	out, err := r.Run(ctx, resolvedPath, "--version")
	if err != nil {
		return nil, fmt.Errorf("failed to run nmap --version: %w", err)
	}

	matches := versionRegex.FindStringSubmatch(string(out))
	if len(matches) < 3 {
		return nil, fmt.Errorf("unable to parse nmap version from output: %q", strings.TrimSpace(string(out)))
	}

	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return nil, fmt.Errorf("invalid major version: %w", err)
	}
	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		return nil, fmt.Errorf("invalid minor version: %w", err)
	}

	// Below 7.80 is fatal
	if major < 7 || (major == 7 && minor < 80) {
		return nil, fmt.Errorf("nmap version %d.%02d is below minimum required version 7.80", major, minor)
	}

	caps := &model.Capabilities{
		NmapPath:    resolvedPath,
		NmapVersion: fmt.Sprintf("%d.%s", major, matches[2]),
		Warnings:    make([]string, 0),
	}

	// Check vulnerability script
	vulnScript := cfg.VulnScript
	if vulnScript == "" {
		vulnScript = "vulners"
	}

	scriptOut, scriptErr := r.Run(ctx, resolvedPath, "--script-help", vulnScript)
	if scriptErr == nil && strings.Contains(string(scriptOut), vulnScript) {
		caps.VulnScriptOK = true
	} else {
		caps.VulnScriptOK = false
		caps.Warnings = append(caps.Warnings, fmt.Sprintf("vulnerability script %q unavailable or failed to initialize", vulnScript))
	}

	// Check raw socket privileges
	rawSocket := false
	if os.Geteuid() == 0 {
		rawSocket = true
	} else if runtime.GOOS == "darwin" {
		// On macOS, desktop capture uses /dev/bpf* packet filter devices.
		// Setuid root on Nmap is explicitly avoided because Darwin kernel restricts bind()
		// during TCP connect version probes (mksock_bind_addr error 22 -> tcpwrapped).
		// When /dev/bpf* is readable/writable, macOS operates in privileged desktop mode.
		if bpfFi, err := os.Stat("/dev/bpf0"); err == nil && bpfFi.Mode().Perm()&0006 != 0 {
			rawSocket = true
		} else if IsSetuidRoot(resolvedPath) {
			rawSocket = true
		}
	} else {
		getcapPath, getcapLookErr := look("getcap")
		if getcapLookErr == nil && getcapPath != "" {
			if capOut, capErr := r.Run(ctx, getcapPath, resolvedPath); capErr == nil {
				if strings.Contains(string(capOut), "cap_net_raw") {
					rawSocket = true
				}
			}
		} else {
			if capOut, capErr := r.Run(ctx, "getcap", resolvedPath); capErr == nil {
				if strings.Contains(string(capOut), "cap_net_raw") {
					rawSocket = true
				}
			}
		}
		if !rawSocket && IsSetuidRoot(resolvedPath) {
			rawSocket = true
		}
	}
	caps.RawSocket = rawSocket

	// EffectiveMode = privileged iff raw && !cfg.ForceUnprivileged
	if rawSocket && !cfg.ForceUnprivileged {
		caps.EffectiveMode = "privileged"
	} else {
		caps.EffectiveMode = "unprivileged"
		if !rawSocket && !cfg.ForceUnprivileged {
			caps.Warnings = append(caps.Warnings, "raw socket access not available (requires root or cap_net_raw); running in unprivileged mode")
		}
	}

	return caps, nil
}
