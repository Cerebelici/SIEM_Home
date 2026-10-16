package scanner_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/scanner"
)

type customRunner struct {
	runFunc func(ctx context.Context, name string, args ...string) ([]byte, error)
	called  bool
}

func (c *customRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	c.called = true
	if c.runFunc != nil {
		return c.runFunc(ctx, name, args...)
	}
	return nil, nil
}

func TestPreflight_NmapMissing(t *testing.T) {
	look := func(string) (string, error) {
		return "", errors.New("binary not found")
	}
	cfg := &config.Config{NmapPath: "nmap"}
	runner := &customRunner{}

	_, err := scanner.Preflight(context.Background(), cfg, runner, look)
	if !errors.Is(err, scanner.ErrNmapNotFound) {
		t.Fatalf("expected ErrNmapNotFound, got: %v", err)
	}
}

func TestPreflight_OldVersion(t *testing.T) {
	look := func(string) (string, error) {
		return "/usr/bin/nmap", nil
	}
	runner := &customRunner{
		runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "--version" {
				return []byte("Nmap version 7.70 ( https://nmap.org )\nPlatform: x86_64"), nil
			}
			return nil, nil
		},
	}
	cfg := &config.Config{NmapPath: "nmap"}

	_, err := scanner.Preflight(context.Background(), cfg, runner, look)
	if err == nil {
		t.Fatalf("expected error for Nmap version 7.70, got nil")
	}
	if !strings.Contains(err.Error(), "below minimum required version") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPreflight_VulnersMissing(t *testing.T) {
	look := func(name string) (string, error) {
		return "/usr/bin/" + name, nil
	}
	runner := &customRunner{
		runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "--version" {
				return []byte("Nmap version 7.94 ( https://nmap.org )\nPlatform: x86_64"), nil
			}
			if len(args) > 0 && args[0] == "--script-help" {
				return []byte("NSE: failed to initialize the script engine"), errors.New("script not found")
			}
			return nil, nil
		},
	}
	cfg := &config.Config{
		NmapPath:          "nmap",
		VulnScript:        "vulners",
		ForceUnprivileged: true,
	}

	caps, err := scanner.Preflight(context.Background(), cfg, runner, look)
	if err != nil {
		t.Fatalf("expected no error when vuln script is missing, got: %v", err)
	}
	if caps.VulnScriptOK {
		t.Errorf("expected VulnScriptOK to be false, got true")
	}
	if len(caps.Warnings) == 0 {
		t.Errorf("expected warnings to contain missing script warning, got empty")
	}
	if caps.EffectiveMode != "unprivileged" {
		t.Errorf("expected effective_mode to be unprivileged, got %s", caps.EffectiveMode)
	}
}

func TestExecutor_RejectsOptionLikeTarget(t *testing.T) {
	runner := &customRunner{
		runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return nil, nil
		},
	}
	cfg := &config.Config{NmapPath: "nmap"}
	sc := scanner.NewWithRunner(cfg, runner)

	// Test Discovery scan rejection
	_, err := sc.RunDiscoveryScan(context.Background(), "--script=evil")
	if err == nil {
		t.Fatalf("expected error when target starts with '-', got nil")
	}
	if runner.called {
		t.Fatalf("command runner should never be called when target starts with '-'")
	}

	// Test Vulnerability scan rejection
	_, err = sc.RunVulnerabilityScan(context.Background(), []string{"--script=evil"})
	if err == nil {
		t.Fatalf("expected error when vuln target starts with '-', got nil")
	}
	if runner.called {
		t.Fatalf("command runner should never be called when target starts with '-'")
	}
}

func TestExecutor_PartialXMLIsFailure(t *testing.T) {
	partialXML := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sn 172.28.0.0/24">
  <host>
    <status state="up"/>
    <address addr="172.28.0.10" addrtype="ipv4"/>
  </host>
</nmaprun>`

	runner := &customRunner{
		runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return []byte(partialXML), errors.New("exit status 1")
		},
	}
	cfg := &config.Config{NmapPath: "nmap"}
	sc := scanner.NewWithRunner(cfg, runner)

	_, err := sc.RunDiscoveryScan(context.Background(), "172.28.0.0/24")
	if err == nil {
		t.Fatalf("expected error for partial XML without runstats/exit=success, got nil")
	}

	_, err = sc.RunVulnerabilityScan(context.Background(), []string{"172.28.0.10"})
	if err == nil {
		t.Fatalf("expected error for partial XML without runstats/exit=success, got nil")
	}
}

func TestPreflight_SuccessPrivileged(t *testing.T) {
	look := func(name string) (string, error) {
		return "/usr/bin/" + name, nil
	}
	runner := &customRunner{
		runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if len(args) > 0 && args[0] == "--version" {
				return []byte("Nmap version 7.94 ( https://nmap.org )"), nil
			}
			if len(args) > 0 && args[0] == "--script-help" {
				return []byte("vulners: https://vulners.com"), nil
			}
			if name == "/usr/bin/getcap" {
				return []byte("/usr/bin/nmap cap_net_raw+ep"), nil
			}
			return nil, nil
		},
	}
	cfg := &config.Config{
		NmapPath:   "nmap",
		VulnScript: "vulners",
	}

	caps, err := scanner.Preflight(context.Background(), cfg, runner, look)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !caps.VulnScriptOK {
		t.Errorf("expected VulnScriptOK to be true")
	}
	if !caps.RawSocket {
		t.Errorf("expected RawSocket to be true from cap_net_raw")
	}
	if caps.EffectiveMode != "privileged" {
		t.Errorf("expected EffectiveMode to be privileged, got: %s", caps.EffectiveMode)
	}
}

func TestScanner_CapabilitiesAndMethods(t *testing.T) {
	cfg := &config.Config{NmapPath: "nmap"}
	sc := scanner.New(cfg)
	if sc == nil {
		t.Fatal("expected scanner instance, got nil")
	}

	caps := &model.Capabilities{
		NmapPath:      "/usr/bin/nmap",
		NmapVersion:   "7.94",
		EffectiveMode: "privileged",
	}
	sc.SetCapabilities(caps)
	if sc.Capabilities() != caps {
		t.Errorf("expected capabilities to match")
	}
}

func TestScanner_PortSelection(t *testing.T) {
	validXML := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap" start="1690000000" version="7.94">
  <host><status state="up"/><address addr="172.28.0.10" addrtype="ipv4"/></host>
  <runstats><finished exit="success"/></runstats>
</nmaprun>`

	tests := []struct {
		name          string
		scanPorts     string
		expectedFlag  string
		expectedValue string
	}{
		{
			name:          "default to top 2000 ports",
			scanPorts:     "",
			expectedFlag:  "--top-ports",
			expectedValue: "2000",
		},
		{
			name:          "custom port range",
			scanPorts:     "1-10000",
			expectedFlag:  "-p",
			expectedValue: "1-10000",
		},
		{
			name:          "custom port list with -p prefix",
			scanPorts:     "-p 21,22,80,3000,6379",
			expectedFlag:  "-p",
			expectedValue: "21,22,80,3000,6379",
		},
		{
			name:          "custom top ports option",
			scanPorts:     "--top-ports 500",
			expectedFlag:  "--top-ports",
			expectedValue: "500",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var capturedArgs []string
			runner := &customRunner{
				runFunc: func(ctx context.Context, name string, args ...string) ([]byte, error) {
					capturedArgs = args
					return []byte(validXML), nil
				},
			}
			cfg := &config.Config{
				NmapPath:  "nmap",
				ScanPorts: tc.scanPorts,
			}
			sc := scanner.NewWithRunner(cfg, runner)
			_, err := sc.RunVulnerabilityScan(context.Background(), []string{"172.28.0.10"})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			found := false
			for i := 0; i < len(capturedArgs)-1; i++ {
				if capturedArgs[i] == tc.expectedFlag && capturedArgs[i+1] == tc.expectedValue {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %s %s in args, got: %v", tc.expectedFlag, tc.expectedValue, capturedArgs)
			}
		})
	}
}

