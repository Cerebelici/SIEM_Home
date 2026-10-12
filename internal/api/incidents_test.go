package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/api"
	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/scheduler"
	"github.com/gr0gu/cerberus/internal/storage"
)

func setupIncidentAPITest(t *testing.T) (*api.Server, http.Handler, *storage.Storage, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "api_incident_test_*")
	if err != nil {
		t.Fatalf("temp dir error: %v", err)
	}

	store, err := storage.New(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("storage error: %v", err)
	}

	cfg := &config.Config{
		ServerHost:            "127.0.0.1",
		ServerPort:            8080,
		NetworkCIDR:           "172.28.0.0/24",
		DiscoveryInterval:     10 * time.Minute,
		VulnerabilityInterval: 10 * time.Minute,
		NmapPath:              "nmap",
		EnrollToken:           "secret-enroll-token",
		IngestShards:          4,
	}

	scn := scanner.NewWithRunner(cfg, &dummyCmdRunner{})
	sched := scheduler.New(cfg, store, scn)
	server := api.NewServer(cfg, store, sched)

	cleanup := func() {
		_ = server.Shutdown(context.Background())
		store.Close()
		os.RemoveAll(tmpDir)
	}

	return server, server.Handler(), store, cleanup
}

func TestIncidents_EndToEnd_TelemetryToIncident(t *testing.T) {
	_, handler, store, cleanup := setupIncidentAPITest(t)
	defer cleanup()

	ctx := context.Background()

	// 1. Create a network device and an enrolled agent bound to it
	now := time.Now().UTC()
	devToInsert := &model.Device{
		IP:        "192.168.1.100",
		MAC:       "02:42:ac:11:00:02",
		Hostname:  "victim-host",
		Vendor:    "Linux",
		Status:    "up",
		FirstSeen: now,
		LastSeen:  now,
	}
	dev, _, err := store.UpsertDevice(ctx, devToInsert)
	if err != nil {
		t.Fatalf("failed to insert device: %v", err)
	}

	agentID := "11111111-2222-3333-4444-555555555555"
	rawToken := "agent-raw-token-abcdef"
	tokenHash := sha256.Sum256([]byte(rawToken))

	err = store.EnrollAgent(ctx, agentID, "victim-host", tokenHash[:])
	if err != nil {
		t.Fatalf("failed to enroll agent: %v", err)
	}
	// Bind agent to device
	_, err = store.RawWriter().Exec("UPDATE agents SET device_id = ? WHERE agent_id = ?", dev.ID, agentID)
	if err != nil {
		t.Fatalf("failed to bind agent to device: %v", err)
	}

	// 2. Prepare Golden Reverse Shell Telemetry Batch (nginx -> bash -> connect to 203.0.113.7:4444)
	t0 := now.Add(-5 * time.Second)
	batch := model.TelemetryBatch{
		SchemaVersion: 1,
		Agent: model.AgentInfo{
			AgentID:      agentID,
			BootID:       "boot-e2e-1",
			Hostname:     "victim-host",
			AgentVersion: "0.1.0",
			Kernel:       "6.8.0",
			Interfaces: []model.AgentInterface{
				{Name: "eth0", MAC: "02:42:ac:11:00:02", IPv4: []string{"192.168.1.100"}},
			},
		},
		Batch: model.BatchHeader{
			Seq:              1,
			SentAt:           now,
			DroppedSinceLast: 0,
		},
		Events: []model.RawEvent{
			{
				Type: "EXEC",
				TS:   t0,
				PID:  50,
				PPID: 1,
				Comm: "nginx",
				Data: json.RawMessage(`{"filename":"/usr/sbin/nginx"}`),
			},
			{
				Type: "EXEC",
				TS:   t0.Add(1 * time.Second),
				PID:  100,
				PPID: 50,
				Comm: "bash",
				Data: json.RawMessage(`{"filename":"/bin/bash"}`),
			},
			{
				Type: "CONNECT",
				TS:   t0.Add(2 * time.Second),
				PID:  100,
				PPID: 50,
				Comm: "bash",
				Data: json.RawMessage(`{"family":"inet","dst_ip":"203.0.113.7","dst_port":4444}`),
			},
		},
	}

	bodyBytes, _ := json.Marshal(batch)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/telemetry", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("X-Cerberus-Agent-Id", agentID)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected telemetry 202 Accepted, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. Poll GET /api/incidents within 2 seconds
	var incidents []model.Incident
	deadline := time.Now().Add(2 * time.Second)
	found := false

	for time.Now().Before(deadline) {
		getReq := httptest.NewRequest(http.MethodGet, "/api/incidents", nil)
		getRec := httptest.NewRecorder()
		handler.ServeHTTP(getRec, getReq)

		if getRec.Code == http.StatusOK {
			incidents = nil
			if err := json.NewDecoder(getRec.Body).Decode(&incidents); err == nil && len(incidents) > 0 {
				found = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !found || len(incidents) == 0 {
		t.Fatalf("timed out waiting for incident generation within 2 seconds (incidents=%v)", incidents)
	}

	inc := incidents[0]
	if inc.RuleID != "CRB-R001" {
		t.Errorf("expected RuleID CRB-R001, got %s", inc.RuleID)
	}
	if inc.Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL severity, got %s", inc.Severity)
	}
	if inc.DeviceID == nil || *inc.DeviceID != dev.ID {
		t.Errorf("expected bound device_id %d, got %v", dev.ID, inc.DeviceID)
	}

	// 4. Test GET /api/incidents/{id} with joined evidence events
	idReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/incidents/%d", inc.ID), nil)
	idRec := httptest.NewRecorder()
	handler.ServeHTTP(idRec, idReq)

	if idRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from GET /api/incidents/{id}, got %d: %s", idRec.Code, idRec.Body.String())
	}

	var fetchedInc model.Incident
	if err := json.NewDecoder(idRec.Body).Decode(&fetchedInc); err != nil {
		t.Fatalf("failed to decode incident details: %v", err)
	}
	if len(fetchedInc.EvidenceEvents) == 0 {
		t.Errorf("expected joined evidence events in incident detail, got 0")
	}

	// 5. Test PATCH /api/incidents/{id} to update status
	patchBody := bytes.NewReader([]byte(`{"status":"acknowledged"}`))
	patchReq := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/incidents/%d", inc.ID), patchBody)
	patchReq.Header.Set("Content-Type", "application/json")
	patchRec := httptest.NewRecorder()
	handler.ServeHTTP(patchRec, patchReq)

	if patchRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from PATCH /api/incidents/{id}, got %d: %s", patchRec.Code, patchRec.Body.String())
	}

	var patchedInc model.Incident
	_ = json.NewDecoder(patchRec.Body).Decode(&patchedInc)
	if patchedInc.Status != "acknowledged" {
		t.Errorf("expected status 'acknowledged', got %s", patchedInc.Status)
	}

	// 6. Test GET /api/status includes DEV-03 fields
	statusReq := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	statusRec := httptest.NewRecorder()
	handler.ServeHTTP(statusRec, statusReq)

	if statusRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from GET /api/status, got %d", statusRec.Code)
	}

	var sysStatus model.SystemStatus
	if err := json.NewDecoder(statusRec.Body).Decode(&sysStatus); err != nil {
		t.Fatalf("failed to decode SystemStatus: %v", err)
	}

	if sysStatus.IngestEventsTotal < 3 {
		t.Errorf("expected ingest_events_total >= 3, got %d", sysStatus.IngestEventsTotal)
	}
	if sysStatus.IncidentsOpen < 0 {
		t.Errorf("expected incidents_open >= 0, got %d", sysStatus.IncidentsOpen)
	}
}

func TestIncidents_Filters_And_ErrorHandling(t *testing.T) {
	_, handler, store, cleanup := setupIncidentAPITest(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC()

	_ = store.EnrollAgent(ctx, "agent-a", "host-a", []byte("hash-a"))
	_ = store.EnrollAgent(ctx, "agent-b", "host-b", []byte("hash-b"))

	// Insert test incidents directly into storage
	_, _, _ = store.UpsertIncident(ctx, &model.Incident{
		AgentID:          "agent-a",
		RuleID:           "CRB-R003",
		RulesetVersion:   "1.0.0",
		Title:            "Memory injection",
		Severity:         "HIGH",
		Score:            7.5,
		DedupeKey:        "dedupe-a",
		FirstSeenAt:      now,
		LastSeenAt:       now,
		HitCount:         1,
		EvidenceEventIDs: []int64{1},
		Status:           "open",
	}, 5*time.Minute)

	_, _, _ = store.UpsertIncident(ctx, &model.Incident{
		AgentID:          "agent-b",
		RuleID:           "CRB-R007",
		RulesetVersion:   "1.0.0",
		Title:            "Shadow tamper",
		Severity:         "CRITICAL",
		Score:            9.5,
		DedupeKey:        "dedupe-b",
		FirstSeenAt:      now,
		LastSeenAt:       now,
		HitCount:         1,
		EvidenceEventIDs: []int64{2},
		Status:           "closed",
	}, 5*time.Minute)

	// Filter by severity=CRITICAL
	req := httptest.NewRequest(http.MethodGet, "/api/incidents?severity=CRITICAL", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var list []model.Incident
	_ = json.NewDecoder(rec.Body).Decode(&list)
	if len(list) != 1 || list[0].Severity != "CRITICAL" {
		t.Errorf("expected 1 CRITICAL incident, got %d", len(list))
	}

	// 404 for non-existent incident
	req404 := httptest.NewRequest(http.MethodGet, "/api/incidents/99999", nil)
	rec404 := httptest.NewRecorder()
	handler.ServeHTTP(rec404, req404)
	if rec404.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent incident, got %d", rec404.Code)
	}

	// Bad status in PATCH
	badPatch := httptest.NewRequest(http.MethodPatch, "/api/incidents/1", bytes.NewReader([]byte(`{"status":"invalid_status"}`)))
	badRec := httptest.NewRecorder()
	handler.ServeHTTP(badRec, badPatch)
	if badRec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad status, got %d", badRec.Code)
	}
}
