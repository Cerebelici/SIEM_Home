package scheduler_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/scheduler"
	"github.com/gr0gu/cerberus/internal/storage"
)

type dummyRunner struct{}

func (d *dummyRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return []byte(`<nmaprun scanner="nmap"></nmaprun>`), nil
}

func TestScheduler_Lifecycle(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "scheduler_test_*")
	if err != nil {
		t.Fatalf("temp dir error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.New(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("storage init error: %v", err)
	}
	defer store.Close()

	cfg := &config.Config{
		NetworkCIDR:           "172.28.0.0/24",
		DiscoveryInterval:     100 * time.Millisecond,
		VulnerabilityInterval: 100 * time.Millisecond,
		ScanTimeout:           500 * time.Millisecond,
		NmapPath:              "nmap",
	}

	scn := scanner.NewWithRunner(cfg, &dummyRunner{})
	sch := scheduler.New(cfg, store, scn)

	ctx, cancel := context.WithCancel(context.Background())

	sch.Start(ctx)

	// Test EnqueueImmediateScan
	sch.EnqueueImmediateScan("172.28.0.99")

	time.Sleep(150 * time.Millisecond)

	discTime, vulnTime, _, _ := sch.GetNextRuns()
	if discTime == nil {
		t.Errorf("expected discovery next run time to be populated")
	}
	if vulnTime == nil {
		t.Errorf("expected vuln next run time to be populated")
	}

	// Graceful Stop
	cancel()
	sch.Stop()
}

type sequenceRunner struct {
	vulnOutputs [][]byte
	vulnIdx     int
}

func (s *sequenceRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	for _, a := range args {
		if a == "-sV" || strings.Contains(a, "script") {
			if s.vulnIdx < len(s.vulnOutputs) {
				out := s.vulnOutputs[s.vulnIdx]
				s.vulnIdx++
				return out, nil
			}
			return []byte(`<nmaprun scanner="nmap"></nmaprun>`), nil
		}
	}
	return []byte(`<nmaprun scanner="nmap"></nmaprun>`), nil
}

func TestScheduler_VulnerabilityReconciliation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "scheduler_recon_test_*")
	if err != nil {
		t.Fatalf("temp dir error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.New(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("storage init error: %v", err)
	}
	defer store.Close()

	scan1XML := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 172.28.0.10" start="1690000000" version="7.94">
  <host>
    <status state="up"/>
    <address addr="172.28.0.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
        <script id="vulners" output="CVE-2021-23017 7.5"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	scan2XML := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 172.28.0.10" start="1690000010" version="7.94">
  <host>
    <status state="up"/>
    <address addr="172.28.0.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	runner := &sequenceRunner{
		vulnOutputs: [][]byte{[]byte(scan1XML), []byte(scan2XML)},
	}

	cfg := &config.Config{
		NetworkCIDR:           "172.28.0.0/24",
		DiscoveryInterval:     10 * time.Second,
		VulnerabilityInterval: 10 * time.Second,
		ScanTimeout:           2 * time.Second,
		NmapPath:              "nmap",
	}

	scn := scanner.NewWithRunner(cfg, runner)
	sch := scheduler.New(cfg, store, scn)

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		sch.Stop()
	}()

	sch.Start(ctx)

	// 1. First immediate scan detects vuln
	sch.EnqueueImmediateScan("172.28.0.10")
	time.Sleep(200 * time.Millisecond)

	dev, err := store.GetDeviceByIP(ctx, "172.28.0.10")
	if err != nil || dev == nil {
		t.Fatalf("expected device created: %v", err)
	}

	isVuln, count, _, err := store.GetDeviceSecurityPosture(ctx, dev.ID)
	if err != nil {
		t.Fatalf("posture error: %v", err)
	}
	if !isVuln || count != 1 {
		t.Errorf("expected isVuln=true, count=1 after scan 1, got %v, %d", isVuln, count)
	}

	// 2. Second scan resolves vuln
	sch.EnqueueImmediateScan("172.28.0.10")
	time.Sleep(200 * time.Millisecond)

	isVuln, count, _, err = store.GetDeviceSecurityPosture(ctx, dev.ID)
	if err != nil {
		t.Fatalf("posture error: %v", err)
	}
	if isVuln || count != 0 {
		t.Errorf("expected isVuln=false, count=0 after scan 2, got %v, %d", isVuln, count)
	}

	vulns, err := store.GetAllVulnerabilities(ctx, "")
	if err != nil {
		t.Fatalf("get all vulns error: %v", err)
	}
	if len(vulns) != 1 || vulns[0].Status != "resolved" || vulns[0].ResolvedAt == nil {
		t.Errorf("expected 1 resolved vuln with resolved_at, got %+v", vulns)
	}
}

func TestScheduler_Triggers(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "scheduler_trigger_test_*")
	if err != nil {
		t.Fatalf("temp dir error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.New(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("storage init error: %v", err)
	}
	defer store.Close()

	cfg := &config.Config{
		NetworkCIDR:           "172.28.0.0/24",
		DiscoveryInterval:     10 * time.Second,
		VulnerabilityInterval: 10 * time.Second,
		ScanTimeout:           2 * time.Second,
		NmapPath:              "nmap",
	}

	scn := scanner.NewWithRunner(cfg, &dummyRunner{})
	sch := scheduler.New(cfg, store, scn)

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		sch.Stop()
	}()

	sch.Start(ctx)

	// Test TriggerDiscovery and TriggerVulnerabilityScan
	if err := sch.TriggerDiscovery(ctx); err != nil {
		t.Fatalf("trigger discovery error: %v", err)
	}
	if err := sch.TriggerVulnerabilityScan(ctx); err != nil {
		t.Fatalf("trigger vuln scan error: %v", err)
	}
}
