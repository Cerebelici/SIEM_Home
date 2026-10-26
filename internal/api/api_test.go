package api_test

import (
	"context"
	"encoding/json"
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

type dummyCmdRunner struct{}

func (d *dummyCmdRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return []byte(`<nmaprun scanner="nmap"></nmaprun>`), nil
}

func setupAPITest(t *testing.T) (http.Handler, *storage.Storage, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "api_test_*")
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
	}

	scn := scanner.NewWithRunner(cfg, &dummyCmdRunner{})
	sched := scheduler.New(cfg, store, scn)
	server := api.NewServer(cfg, store, sched)

	cleanup := func() {
		store.Close()
		os.RemoveAll(tmpDir)
	}

	return server.Handler(), store, cleanup
}

func TestAPI_Status(t *testing.T) {
	handler, _, cleanup := setupAPITest(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var status model.SystemStatus
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatalf("json decode error: %v", err)
	}

	if status.TotalDevices != 0 {
		t.Errorf("expected 0 total devices initially, got %d", status.TotalDevices)
	}

	if status.Capabilities == nil {
		t.Fatalf("expected capabilities object in /api/status, got nil")
	}
	if status.Capabilities.EffectiveMode == "" {
		t.Errorf("expected non-empty effective_mode in capabilities")
	}
}

func TestAPI_DevicesAndDetails(t *testing.T) {
	handler, store, cleanup := setupAPITest(t)
	defer cleanup()

	ctx := context.Background()

	// Seed database with a device
	dev, _, err := store.UpsertDevice(ctx, &model.Device{
		IP:       "172.28.0.10",
		MAC:      "02:42:AC:1C:00:0A",
		Hostname: "target-nginx",
		Vendor:   "Docker",
		Status:   "up",
	})
	if err != nil {
		t.Fatalf("failed to insert device: %v", err)
	}

	// Seed service
	_, err = store.UpsertService(ctx, &model.Service{
		DeviceID:    dev.ID,
		Port:        80,
		Protocol:    "tcp",
		ServiceName: "http",
		Product:     "nginx",
		Version:     "1.21.6",
		State:       "open",
	})
	if err != nil {
		t.Fatalf("failed to insert service: %v", err)
	}

	// Seed vulnerability
	_, _, err = store.UpsertVulnerability(ctx, &model.Vulnerability{
		DeviceID:    dev.ID,
		ServicePort: 80,
		CVEID:       "CVE-2021-23017",
		Title:       "1-byte memory overwrite in resolver",
		Severity:    "HIGH",
		CVSSScore:   7.5,
	})
	if err != nil {
		t.Fatalf("failed to insert vulnerability: %v", err)
	}

	// 1. GET /api/devices
	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var devList struct {
		Count   int            `json:"count"`
		Devices []model.Device `json:"devices"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&devList); err != nil {
		t.Fatalf("decode devices error: %v", err)
	}
	if devList.Count != 1 || len(devList.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", devList.Count)
	}
	if devList.Devices[0].ServicesCount != 1 || devList.Devices[0].VulnerabilitiesCount != 1 {
		t.Errorf("unexpected counts on device: %+v", devList.Devices[0])
	}

	// 2. GET /api/devices/{id}
	reqDetail := httptest.NewRequest(http.MethodGet, "/api/devices/1", nil)
	recDetail := httptest.NewRecorder()
	handler.ServeHTTP(recDetail, reqDetail)

	if recDetail.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recDetail.Code)
	}

	var singleDev model.Device
	if err := json.NewDecoder(recDetail.Body).Decode(&singleDev); err != nil {
		t.Fatalf("decode single device error: %v", err)
	}
	if len(singleDev.Services) != 1 || len(singleDev.Vulnerabilities) != 1 {
		t.Errorf("expected 1 service and 1 vuln in detailed view, got %d and %d",
			len(singleDev.Services), len(singleDev.Vulnerabilities))
	}

	// 3. GET /api/vulnerabilities
	reqVulns := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities?severity=HIGH", nil)
	recVulns := httptest.NewRecorder()
	handler.ServeHTTP(recVulns, reqVulns)

	if recVulns.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recVulns.Code)
	}

	var vulnList struct {
		Count           int                   `json:"count"`
		Vulnerabilities []model.Vulnerability `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(recVulns.Body).Decode(&vulnList); err != nil {
		t.Fatalf("decode vulns error: %v", err)
	}
	if vulnList.Count != 1 {
		t.Errorf("expected 1 high vuln, got %d", vulnList.Count)
	}

	// 4. GET /api/export/json
	reqExport := httptest.NewRequest(http.MethodGet, "/api/export/json", nil)
	recExport := httptest.NewRecorder()
	handler.ServeHTTP(recExport, reqExport)

	if recExport.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recExport.Code)
	}

	var export model.ExportData
	if err := json.NewDecoder(recExport.Body).Decode(&export); err != nil {
		t.Fatalf("decode export error: %v", err)
	}
	if export.TotalDevices != 1 || export.TotalVulnerabilities != 1 {
		t.Errorf("unexpected export data: %+v", export)
	}

	// 5. Test CORS Preflight
	reqCors := httptest.NewRequest(http.MethodOptions, "/api/devices", nil)
	recCors := httptest.NewRecorder()
	handler.ServeHTTP(recCors, reqCors)

	if recCors.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected CORS header *, got %s", recCors.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestAPI_Timeline(t *testing.T) {
	handler, store, cleanup := setupAPITest(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC()

	// Seed scan log
	scan, err := store.CreateScanLog(ctx, &model.ScanLog{
		ScanType:   "discovery",
		Status:     "completed",
		TargetSpec: "172.28.0.0/24",
		HostsFound: 1,
		StartedAt:  now.Add(-10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("create scan log error: %v", err)
	}

	// Seed device
	dev, _, err := store.UpsertDevice(ctx, &model.Device{
		IP:       "172.28.0.10",
		MAC:      "02:42:AC:1C:00:0A",
		Hostname: "target-nginx",
		Vendor:   "Docker",
		Status:   "up",
	})
	if err != nil {
		t.Fatalf("failed to insert device: %v", err)
	}

	// Seed observation
	err = store.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{
		DeviceID:     dev.ID,
		ScanID:       scan.ID,
		Status:       "up",
		IsVulnerable: false,
		VulnsCount:   0,
		MaxSeverity:  "NONE",
		RecordedAt:   now.Add(-10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("failed to record scan observation: %v", err)
	}

	// Request GET /api/timeline
	req := httptest.NewRequest(http.MethodGet, "/api/timeline", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var timeline model.TimelineResponse
	if err := json.NewDecoder(rec.Body).Decode(&timeline); err != nil {
		t.Fatalf("decode timeline error: %v", err)
	}

	if len(timeline.ScanTicks) != 1 {
		t.Errorf("expected 1 scan tick, got %d", len(timeline.ScanTicks))
	}
	if len(timeline.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(timeline.Devices))
	}
	if len(timeline.Devices[0].Periods) != 1 {
		t.Fatalf("expected 1 period, got %d", len(timeline.Devices[0].Periods))
	}

	period := timeline.Devices[0].Periods[0]
	if period.Status != "up" || period.IsVulnerable || period.MaxSeverity != "NONE" {
		t.Errorf("unexpected period: %+v", period)
	}
}
