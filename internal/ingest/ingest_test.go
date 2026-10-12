package ingest_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/api"
	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/ingest"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/scheduler"
	"github.com/gr0gu/cerberus/internal/storage"
)

type dummyRunner struct{}

func (d *dummyRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return []byte(`<nmaprun scanner="nmap"></nmaprun>`), nil
}

func setupTestApp(t *testing.T) (http.Handler, *storage.Storage, *config.Config, string, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "cerberus_ingest_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := storage.New(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to create storage: %v", err)
	}

	cfg := &config.Config{
		ServerHost:            "127.0.0.1",
		ServerPort:            8080,
		DBPath:                dbPath,
		NetworkCIDR:           "172.28.0.0/24",
		DiscoveryInterval:     10 * time.Minute,
		VulnerabilityInterval: 10 * time.Minute,
		ScanTimeout:           2 * time.Second,
		NmapPath:              "nmap",
		EnrollToken:           "test-enroll-secret-12345",
		IngestMaxBody:         1048576,
		IngestShards:          4,
		EventRetention:        168 * time.Hour,
	}

	sched := scheduler.New(cfg, store, nil)
	srv := api.NewServer(cfg, store, sched)

	cleanup := func() {
		_ = srv.Shutdown(context.Background())
		_ = store.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return srv.Handler(), store, cfg, dbPath, cleanup
}

func TestEnroll_SuccessAndRawTokenNotInDB(t *testing.T) {
	handler, _, _, dbPath, cleanup := setupTestApp(t)
	defer cleanup()

	enrollReq := model.AgentEnrollRequest{
		AgentID:         "agent-001",
		Hostname:        "node-01.local",
		EnrollmentToken: "test-enroll-secret-12345",
	}
	body, _ := json.Marshal(enrollReq)

	req := httptest.NewRequest("POST", "/api/v1/agent/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp model.AgentEnrollResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.AgentToken == "" {
		t.Fatalf("expected non-empty agent_token")
	}

	// Assert the raw token string is not anywhere in the SQLite database file bytes
	dbBytes, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("reading DB file bytes: %v", err)
	}
	if bytes.Contains(dbBytes, []byte(resp.AgentToken)) {
		t.Errorf("FATAL: raw agent token found plaintext in SQLite DB file!")
	}
}

func TestEnroll_BadTokenAndDisabled(t *testing.T) {
	handler, _, cfg, _, cleanup := setupTestApp(t)
	defer cleanup()

	// 1. Wrong enrollment token
	reqBody, _ := json.Marshal(model.AgentEnrollRequest{
		AgentID:         "agent-002",
		Hostname:        "node-02",
		EnrollmentToken: "wrong-secret",
	})
	req := httptest.NewRequest("POST", "/api/v1/agent/enroll", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for bad token, got %d", rec.Code)
	}

	// 2. Disabled enrollment
	cfg.EnrollToken = ""
	req = httptest.NewRequest("POST", "/api/v1/agent/enroll", bytes.NewReader(reqBody))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden when enroll token is empty, got %d", rec.Code)
	}
}

func TestTelemetry_AuthScenarios(t *testing.T) {
	handler, _, _, _, cleanup := setupTestApp(t)
	defer cleanup()

	// Enroll agent-10
	enrollReq, _ := json.Marshal(model.AgentEnrollRequest{
		AgentID:         "agent-10",
		Hostname:        "host-10",
		EnrollmentToken: "test-enroll-secret-12345",
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/agent/enroll", bytes.NewReader(enrollReq)))
	var enrollResp model.AgentEnrollResponse
	_ = json.NewDecoder(rec.Body).Decode(&enrollResp)

	dummyPayload := `{"schema_version":1,"agent":{"agent_id":"agent-10","boot_id":"b1","hostname":"host-10"},"batch":{"seq":1,"sent_at":"2026-10-12T20:00:00Z"},"events":[]}`

	// 1. Missing headers -> 401
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/agent/telemetry", strings.NewReader(dummyPayload)))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing auth headers, got %d", rec.Code)
	}

	// 2. Bad token -> 401
	req := httptest.NewRequest("POST", "/api/v1/agent/telemetry", strings.NewReader(dummyPayload))
	req.Header.Set("X-Cerberus-Agent-Id", "agent-10")
	req.Header.Set("Authorization", "Bearer invalid-token-xyz")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for bad token, got %d", rec.Code)
	}

	// 3. Revoked agent -> 401
	recDel := httptest.NewRecorder()
	handler.ServeHTTP(recDel, httptest.NewRequest("DELETE", "/api/agents/agent-10", nil))
	if recDel.Code != http.StatusOK {
		t.Fatalf("expected 200 for agent deletion, got %d", recDel.Code)
	}

	req = httptest.NewRequest("POST", "/api/v1/agent/telemetry", strings.NewReader(dummyPayload))
	req.Header.Set("X-Cerberus-Agent-Id", "agent-10")
	req.Header.Set("Authorization", "Bearer "+enrollResp.AgentToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked agent, got %d", rec.Code)
	}
}

func TestTelemetry_GoldenPayloadAndDuplicate(t *testing.T) {
	handler, store, _, _, cleanup := setupTestApp(t)
	defer cleanup()

	// Read Golden Payload
	goldenBytes, err := os.ReadFile("../../testdata/batch_v1.json")
	if err != nil {
		t.Fatalf("failed to read testdata/batch_v1.json: %v", err)
	}

	var batch model.TelemetryBatch
	if err := json.Unmarshal(goldenBytes, &batch); err != nil {
		t.Fatalf("parsing batch_v1.json: %v", err)
	}

	// Enroll agent matching golden batch
	enrollReq, _ := json.Marshal(model.AgentEnrollRequest{
		AgentID:         batch.Agent.AgentID,
		Hostname:        batch.Agent.Hostname,
		EnrollmentToken: "test-enroll-secret-12345",
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/agent/enroll", bytes.NewReader(enrollReq)))
	var enrollResp model.AgentEnrollResponse
	_ = json.NewDecoder(rec.Body).Decode(&enrollResp)

	// Send golden batch
	req := httptest.NewRequest("POST", "/api/v1/agent/telemetry", bytes.NewReader(goldenBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cerberus-Agent-Id", batch.Agent.AgentID)
	req.Header.Set("Authorization", "Bearer "+enrollResp.AgentToken)
	rec = httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", rec.Code, rec.Body.String())
	}

	var telResp model.TelemetryResponse
	_ = json.NewDecoder(rec.Body).Decode(&telResp)
	if telResp.Accepted != 8 || telResp.Rejected != 0 {
		t.Errorf("expected accepted=8, rejected=0; got %+v", telResp)
	}

	// Verify events in storage
	events, err := store.GetAgentEvents(context.Background(), batch.Agent.AgentID, "", nil, nil, 100)
	if err != nil {
		t.Fatalf("getting events: %v", err)
	}
	if len(events) != 8 {
		t.Fatalf("expected 8 stored events, got %d", len(events))
	}

	// Verify CONNECT event normalized fields: dst_ip and dst_port
	var connectEvent *model.NormalizedEvent
	for _, e := range events {
		if e.Type == "CONNECT" {
			connectEvent = &e
			break
		}
	}
	if connectEvent == nil {
		t.Fatalf("expected CONNECT event stored")
	}
	if !connectEvent.DstIP.IsValid() || connectEvent.DstIP.String() != "1.1.1.1" {
		t.Errorf("expected DstIP 1.1.1.1, got %v", connectEvent.DstIP)
	}
	if connectEvent.DstPort != 443 {
		t.Errorf("expected DstPort 443, got %d", connectEvent.DstPort)
	}

	// Resend exact same batch -> duplicate: true, still 8 rows
	reqDupe := httptest.NewRequest("POST", "/api/v1/agent/telemetry", bytes.NewReader(goldenBytes))
	reqDupe.Header.Set("Content-Type", "application/json")
	reqDupe.Header.Set("X-Cerberus-Agent-Id", batch.Agent.AgentID)
	reqDupe.Header.Set("Authorization", "Bearer "+enrollResp.AgentToken)
	recDupe := httptest.NewRecorder()

	handler.ServeHTTP(recDupe, reqDupe)
	if recDupe.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted for duplicate, got %d", recDupe.Code)
	}

	var dupeResp model.TelemetryResponse
	_ = json.NewDecoder(recDupe.Body).Decode(&dupeResp)
	if !dupeResp.Duplicate {
		t.Errorf("expected duplicate=true, got %+v", dupeResp)
	}

	eventsAfterDupe, _ := store.GetAgentEvents(context.Background(), batch.Agent.AgentID, "", nil, nil, 100)
	if len(eventsAfterDupe) != 8 {
		t.Errorf("expected still 8 events after duplicate resend, got %d", len(eventsAfterDupe))
	}
}

func TestTelemetry_PayloadSizeAndGzipBomb(t *testing.T) {
	handler, _, _, _, cleanup := setupTestApp(t)
	defer cleanup()

	// Enroll agent
	enrollReq, _ := json.Marshal(model.AgentEnrollRequest{
		AgentID:         "agent-size-test",
		Hostname:        "size-node",
		EnrollmentToken: "test-enroll-secret-12345",
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/agent/enroll", bytes.NewReader(enrollReq)))
	var enrollResp model.AgentEnrollResponse
	_ = json.NewDecoder(rec.Body).Decode(&enrollResp)

	// 1. Raw body > 1.5 MiB -> 413
	largeBytes := bytes.Repeat([]byte("A"), 1500000)
	req := httptest.NewRequest("POST", "/api/v1/agent/telemetry", bytes.NewReader(largeBytes))
	req.Header.Set("X-Cerberus-Agent-Id", "agent-size-test")
	req.Header.Set("Authorization", "Bearer "+enrollResp.AgentToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 for 1.5 MiB body, got %d", rec.Code)
	}

	// 2. Gzip bomb: 10 MB of zeros compressed to <10 KB -> 413, no OOM
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write(bytes.Repeat([]byte{0}, 10*1024*1024))
	_ = gw.Close()

	bombReq := httptest.NewRequest("POST", "/api/v1/agent/telemetry", &gzBuf)
	bombReq.Header.Set("Content-Encoding", "gzip")
	bombReq.Header.Set("X-Cerberus-Agent-Id", "agent-size-test")
	bombReq.Header.Set("Authorization", "Bearer "+enrollResp.AgentToken)
	recBomb := httptest.NewRecorder()
	handler.ServeHTTP(recBomb, bombReq)
	if recBomb.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 for gzip bomb, got %d", recBomb.Code)
	}
}

func TestTelemetry_ValidationThresholds(t *testing.T) {
	handler, _, _, _, cleanup := setupTestApp(t)
	defer cleanup()

	// Enroll agent
	enrollReq, _ := json.Marshal(model.AgentEnrollRequest{
		AgentID:         "agent-thresholds",
		Hostname:        "threshold-node",
		EnrollmentToken: "test-enroll-secret-12345",
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/agent/enroll", bytes.NewReader(enrollReq)))
	var enrollResp model.AgentEnrollResponse
	_ = json.NewDecoder(rec.Body).Decode(&enrollResp)

	// 1. 1,001 events -> 400
	oversizedBatch := model.TelemetryBatch{
		SchemaVersion: 1,
		Agent: model.AgentInfo{
			AgentID:  "agent-thresholds",
			BootID:   "boot-1",
			Hostname: "threshold-node",
		},
		Batch: model.BatchHeader{Seq: 1, SentAt: time.Now().UTC()},
	}
	for i := 0; i < 1001; i++ {
		oversizedBatch.Events = append(oversizedBatch.Events, model.RawEvent{
			Type: "EXEC",
			Comm: "test",
			Data: json.RawMessage(`{"filename":"/bin/ls"}`),
		})
	}
	body, _ := json.Marshal(oversizedBatch)
	req := httptest.NewRequest("POST", "/api/v1/agent/telemetry", bytes.NewReader(body))
	req.Header.Set("X-Cerberus-Agent-Id", "agent-thresholds")
	req.Header.Set("Authorization", "Bearer "+enrollResp.AgentToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for 1001 events, got %d", rec.Code)
	}

	// 2. 2 invalid of 10 -> 202 {accepted:8, rejected:2}
	batch10 := model.TelemetryBatch{
		SchemaVersion: 1,
		Agent: model.AgentInfo{
			AgentID:  "agent-thresholds",
			BootID:   "boot-1",
			Hostname: "threshold-node",
		},
		Batch: model.BatchHeader{Seq: 2, SentAt: time.Now().UTC()},
	}
	for i := 0; i < 8; i++ {
		batch10.Events = append(batch10.Events, model.RawEvent{
			Type: "EXEC",
			Comm: "test",
			Data: json.RawMessage(`{"filename":"/bin/ls"}`),
		})
	}
	// 2 invalid events
	batch10.Events = append(batch10.Events, model.RawEvent{
		Type: "EXEC",
		Data: json.RawMessage(`{}`), // missing filename
	})
	batch10.Events = append(batch10.Events, model.RawEvent{
		Type: "CONNECT",
		Data: json.RawMessage(`{"family":"invalid"}`),
	})

	body10, _ := json.Marshal(batch10)
	req = httptest.NewRequest("POST", "/api/v1/agent/telemetry", bytes.NewReader(body10))
	req.Header.Set("X-Cerberus-Agent-Id", "agent-thresholds")
	req.Header.Set("Authorization", "Bearer "+enrollResp.AgentToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for 8 valid + 2 invalid, got %d", rec.Code)
	}
	var resp10 model.TelemetryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp10)
	if resp10.Accepted != 8 || resp10.Rejected != 2 {
		t.Errorf("expected accepted=8, rejected=2; got %+v", resp10)
	}

	// 3. 5 invalid of 10 -> 400
	batch50 := model.TelemetryBatch{
		SchemaVersion: 1,
		Agent: model.AgentInfo{
			AgentID:  "agent-thresholds",
			BootID:   "boot-1",
			Hostname: "threshold-node",
		},
		Batch: model.BatchHeader{Seq: 3, SentAt: time.Now().UTC()},
	}
	for i := 0; i < 5; i++ {
		batch50.Events = append(batch50.Events, model.RawEvent{
			Type: "EXEC",
			Data: json.RawMessage(`{"filename":"/bin/ls"}`),
		})
	}
	for i := 0; i < 5; i++ {
		batch50.Events = append(batch50.Events, model.RawEvent{
			Type: "EXEC",
			Data: json.RawMessage(`{}`), // missing filename
		})
	}
	body50, _ := json.Marshal(batch50)
	req = httptest.NewRequest("POST", "/api/v1/agent/telemetry", bytes.NewReader(body50))
	req.Header.Set("X-Cerberus-Agent-Id", "agent-thresholds")
	req.Header.Set("Authorization", "Bearer "+enrollResp.AgentToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for 5 invalid of 10 events, got %d", rec.Code)
	}
}

func TestTelemetry_InterfaceInventoryUpsert(t *testing.T) {
	handler, store, _, _, cleanup := setupTestApp(t)
	defer cleanup()

	// Enroll agent
	enrollReq, _ := json.Marshal(model.AgentEnrollRequest{
		AgentID:         "agent-iface",
		Hostname:        "iface-node",
		EnrollmentToken: "test-enroll-secret-12345",
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/agent/enroll", bytes.NewReader(enrollReq)))
	var enrollResp model.AgentEnrollResponse
	_ = json.NewDecoder(rec.Body).Decode(&enrollResp)

	// Batch 1: IP = 10.10.10.1
	batch1 := model.TelemetryBatch{
		SchemaVersion: 1,
		Agent: model.AgentInfo{
			AgentID:  "agent-iface",
			BootID:   "b1",
			Hostname: "iface-node",
			Interfaces: []model.AgentInterface{
				{Name: "eth0", MAC: "aa:bb:cc:dd:ee:01", IPv4: []string{"10.10.10.1"}},
			},
		},
		Batch: model.BatchHeader{Seq: 1, SentAt: time.Now().UTC()},
		Events: []model.RawEvent{
			{Type: "EXEC", Comm: "sh", Data: json.RawMessage(`{"filename":"/bin/sh"}`)},
		},
	}
	b1Body, _ := json.Marshal(batch1)
	req := httptest.NewRequest("POST", "/api/v1/agent/telemetry", bytes.NewReader(b1Body))
	req.Header.Set("X-Cerberus-Agent-Id", "agent-iface")
	req.Header.Set("Authorization", "Bearer "+enrollResp.AgentToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("batch 1 failed: %d", rec.Code)
	}

	// Lookup by 10.10.10.1
	a1, err := store.GetAgentByInterfaceIP(context.Background(), "10.10.10.1")
	if err != nil || a1 == nil {
		t.Fatalf("expected agent lookup by 10.10.10.1, got %v", err)
	}

	// Batch 2: IP changed to 10.10.10.2
	batch2 := model.TelemetryBatch{
		SchemaVersion: 1,
		Agent: model.AgentInfo{
			AgentID:  "agent-iface",
			BootID:   "b1",
			Hostname: "iface-node",
			Interfaces: []model.AgentInterface{
				{Name: "eth0", MAC: "aa:bb:cc:dd:ee:01", IPv4: []string{"10.10.10.2"}},
			},
		},
		Batch: model.BatchHeader{Seq: 2, SentAt: time.Now().UTC()},
		Events: []model.RawEvent{
			{Type: "EXEC", Comm: "sh", Data: json.RawMessage(`{"filename":"/bin/sh"}`)},
		},
	}
	b2Body, _ := json.Marshal(batch2)
	req = httptest.NewRequest("POST", "/api/v1/agent/telemetry", bytes.NewReader(b2Body))
	req.Header.Set("X-Cerberus-Agent-Id", "agent-iface")
	req.Header.Set("Authorization", "Bearer "+enrollResp.AgentToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("batch 2 failed: %d", rec.Code)
	}

	// Lookup by 10.10.10.2 returns agent
	a2, err := store.GetAgentByInterfaceIP(context.Background(), "10.10.10.2")
	if err != nil || a2 == nil {
		t.Fatalf("expected agent lookup by 10.10.10.2, got %v", err)
	}

	// Old IP 10.10.10.1 no longer returns agent
	oldAgent, err := store.GetAgentByInterfaceIP(context.Background(), "10.10.10.1")
	if err != nil || oldAgent != nil {
		t.Errorf("expected old IP 10.10.10.1 to be replaced, but got %+v", oldAgent)
	}
}

func TestCORS_NoBrowserAccessOnIngest(t *testing.T) {
	handler, _, _, _, cleanup := setupTestApp(t)
	defer cleanup()

	// Ingestion route must NOT have Access-Control-Allow-Origin
	req := httptest.NewRequest("OPTIONS", "/api/v1/agent/telemetry", nil)
	req.Header.Set("Origin", "http://evil.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if h := rec.Header().Get("Access-Control-Allow-Origin"); h != "" {
		t.Errorf("expected no Access-Control-Allow-Origin on ingestion endpoint, got %q", h)
	}

	// Standard REST route MUST have Access-Control-Allow-Origin
	reqStatus := httptest.NewRequest("OPTIONS", "/api/status", nil)
	reqStatus.Header.Set("Origin", "http://example.com")
	recStatus := httptest.NewRecorder()
	handler.ServeHTTP(recStatus, reqStatus)
	if h := recStatus.Header().Get("Access-Control-Allow-Origin"); h != "*" {
		t.Errorf("expected Access-Control-Allow-Origin: * on /api/status, got %q", h)
	}
}

func TestAgentManagementAndEvents(t *testing.T) {
	handler, _, _, _, cleanup := setupTestApp(t)
	defer cleanup()

	// 1. Enroll agent-mgmt-1
	enrollReq, _ := json.Marshal(model.AgentEnrollRequest{
		AgentID:         "agent-mgmt-1",
		Hostname:        "mgmt-node-1",
		EnrollmentToken: "test-enroll-secret-12345",
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/agent/enroll", bytes.NewReader(enrollReq)))
	var enrollResp model.AgentEnrollResponse
	_ = json.NewDecoder(rec.Body).Decode(&enrollResp)

	// 2. List agents GET /api/agents
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/agents", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET /api/agents, got %d", rec.Code)
	}
	var agentsResp struct {
		Count  int                 `json:"count"`
		Agents []model.AgentRecord `json:"agents"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&agentsResp)
	if agentsResp.Count != 1 || len(agentsResp.Agents) != 1 {
		t.Fatalf("expected 1 agent in list, got %+v", agentsResp)
	}

	// 3. Get agent by ID GET /api/agents/agent-mgmt-1
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/agents/agent-mgmt-1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET /api/agents/agent-mgmt-1, got %d", rec.Code)
	}
	var agentRecord model.AgentRecord
	_ = json.NewDecoder(rec.Body).Decode(&agentRecord)
	if agentRecord.AgentID != "agent-mgmt-1" || agentRecord.Hostname != "mgmt-node-1" {
		t.Errorf("unexpected agent record: %+v", agentRecord)
	}

	// Get non-existent agent -> 404
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/agents/non-existent", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown agent, got %d", rec.Code)
	}

	// 4. Send telemetry event
	batch := model.TelemetryBatch{
		SchemaVersion: 1,
		Agent: model.AgentInfo{
			AgentID:  "agent-mgmt-1",
			BootID:   "boot-m",
			Hostname: "mgmt-node-1",
		},
		Batch: model.BatchHeader{Seq: 1, SentAt: time.Now().UTC()},
		Events: []model.RawEvent{
			{
				Type: "EXEC",
				TS:   time.Now().UTC(),
				Comm: "grep",
				Data: json.RawMessage(`{"filename":"/usr/bin/grep"}`),
			},
		},
	}
	bBody, _ := json.Marshal(batch)
	req := httptest.NewRequest("POST", "/api/v1/agent/telemetry", bytes.NewReader(bBody))
	req.Header.Set("X-Cerberus-Agent-Id", "agent-mgmt-1")
	req.Header.Set("Authorization", "Bearer "+enrollResp.AgentToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}

	// 5. Query events GET /api/agent-events?agent_id=agent-mgmt-1&type=EXEC
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/agent-events?agent_id=agent-mgmt-1&type=EXEC", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET /api/agent-events, got %d", rec.Code)
	}
	var eventsResp struct {
		Count  int                     `json:"count"`
		Events []model.NormalizedEvent `json:"events"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&eventsResp)
	if eventsResp.Count != 1 || len(eventsResp.Events) != 1 {
		t.Errorf("expected 1 event, got %+v", eventsResp)
	}
}

func TestDispatcher_SweeperAndBacklog(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "disp_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := storage.New(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	disp := ingest.NewDispatcher(store, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	disp.Start(ctx)
	defer disp.Stop(context.Background())

	// Test Backlogged check (initially false)
	if disp.IsBacklogged(ctx) {
		t.Errorf("expected IsBacklogged=false initially")
	}

	// Submit empty events (processed immediately)
	disp.Submit(0, []model.NormalizedEvent{})
}

func TestValidateEvent_EdgeCases(t *testing.T) {
	now := time.Now().UTC()

	// 1. Empty event type
	if err := ingest.ValidateEvent(&model.RawEvent{}, now); err == nil {
		t.Errorf("expected error for empty type")
	}

	// 2. Future timestamp clamped
	futureEv := model.RawEvent{
		Type: "EXEC",
		TS:   now.Add(48 * time.Hour),
		Data: json.RawMessage(`{"filename":"/bin/ls"}`),
	}
	if err := ingest.ValidateEvent(&futureEv, now); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if futureEv.TS.After(now.Add(25 * time.Hour)) {
		t.Errorf("expected timestamp clamped within +24h")
	}

	// 3. Past timestamp clamped
	pastEv := model.RawEvent{
		Type: "EXEC",
		TS:   now.Add(-48 * time.Hour),
		Data: json.RawMessage(`{"filename":"/bin/ls"}`),
	}
	if err := ingest.ValidateEvent(&pastEv, now); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pastEv.TS.Before(now.Add(-25 * time.Hour)) {
		t.Errorf("expected timestamp clamped within -24h")
	}

	// 4. Invalid JSON data
	badJSONEv := model.RawEvent{
		Type: "EXEC",
		Data: json.RawMessage(`{bad-json`),
	}
	if err := ingest.ValidateEvent(&badJSONEv, now); err == nil {
		t.Errorf("expected error for bad JSON")
	}

	// 5. String > 512 bytes
	longName := strings.Repeat("A", 600)
	longEv := model.RawEvent{
		Type: "EXEC",
		Data: json.RawMessage(fmt.Sprintf(`{"filename":%q}`, longName)),
	}
	if err := ingest.ValidateEvent(&longEv, now); err == nil {
		t.Errorf("expected error for string > 512 bytes")
	}

	// 6. Unknown event type
	unknownEv := model.RawEvent{
		Type: "UNKNOWN_TYPE_123",
		Data: json.RawMessage(`{"foo":"bar"}`),
	}
	if err := ingest.ValidateEvent(&unknownEv, now); err == nil {
		t.Errorf("expected error for unknown event type")
	}
}

func BenchmarkIngest_1000Events(b *testing.B) {
	tmpDir, err := os.MkdirTemp("", "bench_ingest_*")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := storage.New(dbPath)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	_ = store.EnrollAgent(ctx, "bench-agent", "bench-host", []byte("12345678901234567890123456789012"))

	batch := &model.TelemetryBatch{
		SchemaVersion: 1,
		Agent: model.AgentInfo{
			AgentID:  "bench-agent",
			BootID:   "boot-1",
			Hostname: "bench-host",
		},
		Batch: model.BatchHeader{Seq: 1, SentAt: time.Now().UTC()},
	}

	var events []model.NormalizedEvent
	for i := 0; i < 1000; i++ {
		events = append(events, model.NormalizedEvent{
			AgentID:  "bench-agent",
			BootID:   "boot-1",
			Type:     "EXEC",
			Category: "process",
			Action:   "exec",
			TS:       time.Now().UTC(),
			PID:      100,
			PPID:     1,
			Comm:     "bench",
			Image:    "/usr/bin/bench",
			DataJSON: `{"filename":"/usr/bin/bench"}`,
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch.Batch.Seq = uint64(i + 1)
		_, _, err := store.IngestBatch(ctx, batch, events, 0)
		if err != nil {
			b.Fatal(err)
		}
	}
}
