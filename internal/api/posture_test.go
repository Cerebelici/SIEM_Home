package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/api"
	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/scheduler"
	"github.com/gr0gu/cerberus/internal/storage"
)

func setupPostureTestServer(t *testing.T) (*api.Server, *storage.Storage, func()) {
	t.Helper()
	cfg := &config.Config{
		NetworkCIDR:           "10.0.0.0/24",
		DiscoveryInterval:     10 * time.Minute,
		VulnerabilityInterval: 10 * time.Minute,
		ServerHost:            "127.0.0.1",
		ServerPort:            8080,
		DBPath:                ":memory:",
		IngestShards:          2,
	}

	store, err := storage.New(":memory:")
	if err != nil {
		t.Fatalf("failed to init storage: %v", err)
	}

	scn := scanner.New(cfg, &model.Capabilities{NmapPath: "/usr/bin/nmap", EffectiveMode: "unprivileged"})
	sched := scheduler.New(cfg, store, scn)
	srv := api.NewServer(cfg, store, sched)

	cleanup := func() {
		_ = store.Close()
	}
	return srv, store, cleanup
}

func TestAPI_PostureEndpoints(t *testing.T) {
	srv, store, cleanup := setupPostureTestServer(t)
	defer cleanup()

	ctx := t.Context()
	now := time.Now().UTC()

	// Seed 2 active devices
	d1, _, err := store.UpsertDevice(ctx, &model.Device{
		CurrentIP: "10.0.0.10",
		Hostname:  "web-server",
		Status:    "up",
	})
	if err != nil {
		t.Fatalf("upsert d1: %v", err)
	}

	d2, _, err := store.UpsertDevice(ctx, &model.Device{
		CurrentIP: "10.0.0.20",
		Hostname:  "db-server",
		Status:    "up",
	})
	if err != nil {
		t.Fatalf("upsert d2: %v", err)
	}

	// Add high vuln on d1
	_, err = store.RawWriter().Exec(`INSERT INTO vulnerabilities (
		device_id, service_port, cve_id, title, severity, cvss_score, detected_at, is_exploit, status, first_detected_at, last_seen_at
	) VALUES (?, 80, 'CVE-2023-1001', 'Critical RCE', 'HIGH', 8.5, ?, 0, 'open', ?, ?);`, d1.ID, now, now, now)
	if err != nil {
		t.Fatalf("insert vuln d1: %v", err)
	}

	// 1. Test GET /api/posture
	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/posture status = %d; body: %s", rr.Code, rr.Body.String())
	}

	var report model.PostureReport
	if err := json.Unmarshal(rr.Body.Bytes(), &report); err != nil {
		t.Fatalf("unmarshaling posture report: %v", err)
	}
	if report.ActiveDevices != 2 {
		t.Errorf("expected 2 active devices, got %d", report.ActiveDevices)
	}
	if report.FleetScore == nil {
		t.Fatalf("expected non-nil fleet score")
	}
	if len(report.DeviceScores) != 2 {
		t.Errorf("expected 2 device posture scores, got %d", len(report.DeviceScores))
	}

	// 2. Test GET /api/devices (enriched with risk and score)
	reqDevs := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	rrDevs := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rrDevs, reqDevs)

	if rrDevs.Code != http.StatusOK {
		t.Fatalf("GET /api/devices status = %d", rrDevs.Code)
	}

	var devResp struct {
		Count   int            `json:"count"`
		Devices []model.Device `json:"devices"`
	}
	if err := json.Unmarshal(rrDevs.Body.Bytes(), &devResp); err != nil {
		t.Fatalf("unmarshal devices: %v", err)
	}

	for _, d := range devResp.Devices {
		if d.ID == d1.ID {
			if d.Risk <= 0 {
				t.Errorf("expected d1 risk > 0, got %.2f", d.Risk)
			}
			if d.Score >= 100 {
				t.Errorf("expected d1 score < 100, got %.2f", d.Score)
			}
		} else if d.ID == d2.ID {
			if d.Risk != 0 {
				t.Errorf("expected d2 risk == 0, got %.2f", d.Risk)
			}
			if d.Score != 100 {
				t.Errorf("expected d2 score == 100, got %.2f", d.Score)
			}
		}
	}

	// 3. Test GET /api/status (has fleet_score)
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rrStatus := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rrStatus, reqStatus)

	if rrStatus.Code != http.StatusOK {
		t.Fatalf("GET /api/status status = %d", rrStatus.Code)
	}

	var statusResp model.SystemStatus
	if err := json.Unmarshal(rrStatus.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if statusResp.FleetScore == nil {
		t.Errorf("expected fleet_score in status response, got nil")
	}

	// 4. Test Snapshot & GET /api/posture/history
	_, err = srv.PostureService().Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}

	reqHist := httptest.NewRequest(http.MethodGet, "/api/posture/history", nil)
	rrHist := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rrHist, reqHist)

	if rrHist.Code != http.StatusOK {
		t.Fatalf("GET /api/posture/history status = %d", rrHist.Code)
	}

	var histResp struct {
		Count     int                     `json:"count"`
		Snapshots []model.PostureSnapshot `json:"snapshots"`
	}
	if err := json.Unmarshal(rrHist.Body.Bytes(), &histResp); err != nil {
		t.Fatalf("unmarshal history: %v", err)
	}
	if histResp.Count < 1 {
		t.Errorf("expected at least 1 historical snapshot, got %d", histResp.Count)
	}

	// Test invalid time parameter
	reqBadTime := httptest.NewRequest(http.MethodGet, "/api/posture/history?from=not-a-timestamp", nil)
	rrBadTime := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rrBadTime, reqBadTime)
	if rrBadTime.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad timestamp, got %d", rrBadTime.Code)
	}
}
