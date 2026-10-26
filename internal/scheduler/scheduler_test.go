package scheduler_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/model"
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
	var dev *model.Device
	waitFor(t, "device created by scan 1", func() bool {
		dev, err = store.GetDeviceByIP(ctx, "172.28.0.10")
		if err != nil || dev == nil {
			return false
		}
		isVuln, _, _, _ := store.GetDeviceSecurityPosture(ctx, dev.ID)
		return isVuln
	})

	isVuln, count, _, err := store.GetDeviceSecurityPosture(ctx, dev.ID)
	if err != nil {
		t.Fatalf("posture error: %v", err)
	}
	if !isVuln || count != 1 {
		t.Errorf("expected isVuln=true, count=1 after scan 1, got %v, %d", isVuln, count)
	}

	// 2. Second scan resolves vuln
	sch.EnqueueImmediateScan("172.28.0.10")
	waitFor(t, "vulnerability resolved by scan 2", func() bool {
		isVuln, _, _, _ := store.GetDeviceSecurityPosture(ctx, dev.ID)
		return !isVuln
	})

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

// waitFor polls cond until it is true or fails the test after a few seconds. Scans run on
// worker goroutines, so a fixed sleep is either slow or flaky.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// gatedRunner blocks every nmap call until release is closed, so a scan stays running.
type gatedRunner struct {
	release chan struct{}
}

func (g *gatedRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	select {
	case <-g.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return []byte(`<nmaprun scanner="nmap"><runstats><finished exit="success"/></runstats></nmaprun>`), nil
}

func newSchedulerForTest(t *testing.T, runner scanner.CommandRunner) (*scheduler.Scheduler, *storage.Storage) {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage init error: %v", err)
	}
	cfg := &config.Config{
		NetworkCIDR:           "172.28.0.0/24",
		DiscoveryInterval:     10 * time.Minute,
		VulnerabilityInterval: 10 * time.Minute,
		ScanTimeout:           5 * time.Second,
		NmapPath:              "nmap",
	}
	sch := scheduler.New(cfg, store, scanner.NewWithRunner(cfg, runner))
	ctx, cancel := context.WithCancel(context.Background())
	sch.Start(ctx)
	t.Cleanup(func() {
		cancel()
		sch.Stop()
		store.Close()
	})
	return sch, store
}

func TestScheduler_RequestDiscoveryRejectsWhileRunning(t *testing.T) {
	runner := &gatedRunner{release: make(chan struct{})}
	sch, _ := newSchedulerForTest(t, runner)

	// The startup sweep blocks in the runner.
	waitFor(t, "startup discovery running", func() bool {
		_, _, running, _ := sch.GetNextRuns()
		return running
	})
	if err := sch.RequestDiscovery(); !errors.Is(err, scheduler.ErrScanInProgress) {
		t.Fatalf("expected ErrScanInProgress while a sweep runs, got %v", err)
	}

	close(runner.release)
	waitFor(t, "startup discovery finished", func() bool {
		_, _, running, _ := sch.GetNextRuns()
		return !running
	})

	if err := sch.RequestDiscovery(); err != nil {
		t.Fatalf("expected the request to be accepted when idle, got %v", err)
	}
	if err := sch.RequestDiscovery(); !errors.Is(err, scheduler.ErrScanInProgress) {
		t.Fatalf("expected ErrScanInProgress for a second request, got %v", err)
	}
	waitFor(t, "manual discovery finished", func() bool {
		_, _, running, _ := sch.GetNextRuns()
		return !running
	})
	if err := sch.RequestVulnerabilityScan(); err != nil {
		t.Fatalf("expected the vulnerability request to be accepted, got %v", err)
	}
}

func TestScheduler_SetIntervalsReschedulesRunningWorkers(t *testing.T) {
	sch, _ := newSchedulerForTest(t, &dummyRunner{})

	sch.SetIntervals(2*time.Hour, 3*time.Hour)
	waitFor(t, "workers to apply the new intervals", func() bool {
		disc, vuln, _, _ := sch.GetNextRuns()
		return disc != nil && vuln != nil &&
			time.Until(*disc) > 110*time.Minute && time.Until(*vuln) > 170*time.Minute
	})
	if d, v := sch.Intervals(); d != 2*time.Hour || v != 3*time.Hour {
		t.Errorf("Intervals() = %v, %v; want 2h, 3h", d, v)
	}

	// Only the changed interval restarts its timer.
	_, vulnBefore, _, _ := sch.GetNextRuns()
	sch.SetIntervals(4*time.Hour, 3*time.Hour)
	waitFor(t, "discovery to apply the new interval", func() bool {
		disc, _, _, _ := sch.GetNextRuns()
		return disc != nil && time.Until(*disc) > 230*time.Minute
	})
	if _, vulnAfter, _, _ := sch.GetNextRuns(); !vulnAfter.Equal(*vulnBefore) {
		t.Errorf("vulnerability run moved from %v to %v although its interval did not change", vulnBefore, vulnAfter)
	}
}
