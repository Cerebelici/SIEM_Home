package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/api"
	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/logstream"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/scheduler"
	"github.com/gr0gu/cerberus/internal/storage"
)

// blockingCmdRunner blocks every nmap invocation until release is closed,
// letting the test hold a scan in the "running" state deterministically.
type blockingCmdRunner struct {
	release chan struct{}
}

func (b *blockingCmdRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return []byte(`<nmaprun scanner="nmap"></nmaprun>`), nil
}

func newTriggerTestStore(t *testing.T) (*storage.Storage, *config.Config) {
	t.Helper()
	tmpDir := t.TempDir()
	store, err := storage.New(filepath.Join(tmpDir, "trigger.db"))
	if err != nil {
		t.Fatalf("storage error: %v", err)
	}
	t.Cleanup(func() { _ = store.Close(); _ = os.RemoveAll(tmpDir) })

	cfg := &config.Config{
		ServerHost:            "127.0.0.1",
		ServerPort:            8080,
		NetworkCIDR:           "172.28.0.0/24",
		DiscoveryInterval:     time.Hour,
		VulnerabilityInterval: time.Hour,
		ScanTimeout:           5 * time.Second,
		NmapPath:              "nmap",
	}
	return store, cfg
}

func decodeTriggerBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("json decode error: %v", err)
	}
	return body
}

func TestAPI_TriggerScan_NoScheduler(t *testing.T) {
	store, cfg := newTriggerTestStore(t)
	handler := api.NewServer(cfg, store, nil).Handler()

	for _, path := range []string{"/api/scans/discovery/trigger", "/api/scans/vulnerability/trigger"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: expected 503, got %d", path, rec.Code)
		}
		if body := decodeTriggerBody(t, rec); body["status"] != "unavailable" || body["error"] == "" {
			t.Fatalf("%s: unexpected body %v", path, body)
		}
	}
}

func TestAPI_TriggerScan_ConflictWhileRunning(t *testing.T) {
	store, cfg := newTriggerTestStore(t)
	runner := &blockingCmdRunner{release: make(chan struct{})}
	scn := scanner.NewWithRunner(cfg, runner)
	sched := scheduler.New(cfg, store, scn)
	handler := api.NewServer(cfg, store, sched).Handler()

	ctx, cancel := context.WithCancel(context.Background())
	sched.Start(ctx) // the discovery worker runs an initial sweep, which blocks in the runner
	defer func() {
		close(runner.release)
		cancel()
		sched.Stop()
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		_, _, discRunning, _ := sched.GetNextRuns()
		if discRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("initial discovery sweep never entered the running state")
		}
		time.Sleep(10 * time.Millisecond)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/scans/discovery/trigger", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 while discovery is running, got %d", rec.Code)
	}
	body := decodeTriggerBody(t, rec)
	if body["scan_type"] != "discovery" || !strings.Contains(body["error"], "already in progress") {
		t.Fatalf("unexpected 409 body: %v", body)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/scans/vulnerability/trigger", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for idle vulnerability worker, got %d", rec.Code)
	}
	body = decodeTriggerBody(t, rec)
	if body["status"] != "running" || body["scan_type"] != "vulnerability" || body["message"] == "" {
		t.Fatalf("unexpected 202 body: %v", body)
	}
}

func TestAPI_CORSPreflight_AllowsAPIKeyAndPatch(t *testing.T) {
	handler, _, cleanup := setupAPITest(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodOptions, "/api/scans/discovery/trigger", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "x-api-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for preflight, got %d", rec.Code)
	}
	if h := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(h, "X-API-Key") {
		t.Fatalf("expected X-API-Key in allowed headers, got %q", h)
	}
	if m := rec.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(m, "PATCH") {
		t.Fatalf("expected PATCH in allowed methods, got %q", m)
	}
}

func TestAPI_Logs_ReturnsDaemonLogLines(t *testing.T) {
	store, cfg := newTriggerTestStore(t)
	srv := api.NewServer(cfg, store, nil)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/logs", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"logs":[]`) {
		t.Fatalf("expected an empty log list without a buffer, got %d %s", rec.Code, rec.Body.String())
	}

	logs := logstream.New(10)
	_, _ = logs.Write([]byte("[Discovery] Completed. Discovered 2 live hosts (0 new) in 34000ms\n"))
	srv.SetLogs(logs)

	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/logs", nil))
	var body struct {
		Count int               `json:"count"`
		Logs  []logstream.Entry `json:"logs"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("json decode error: %v", err)
	}
	if body.Count != 1 || body.Logs[0].Source != "Discovery" || body.Logs[0].Level != logstream.LevelInfo {
		t.Fatalf("unexpected logs body: %+v", body)
	}
}

type fakeSettings struct {
	saved model.AppSettings
}

func (f *fakeSettings) GetSettings(context.Context) (*model.SettingsResponse, error) {
	return &model.SettingsResponse{Settings: f.saved}, nil
}

func (f *fakeSettings) UpdateSettings(_ context.Context, req model.AppSettings) (*model.SettingsResponse, error) {
	f.saved = req
	return &model.SettingsResponse{Settings: req}, nil
}

func TestAPI_Settings(t *testing.T) {
	store, cfg := newTriggerTestStore(t)
	srv := api.NewServer(cfg, store, nil)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without a settings provider, got %d", rec.Code)
	}

	provider := &fakeSettings{}
	srv.SetSettingsProvider(provider)

	put := func(remoteAddr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"network_mode":"custom","custom_network_cidr":"10.0.0.0/24"}`))
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	if rec := put("192.168.0.50:51000"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a remote caller without API key, got %d", rec.Code)
	}
	if rec := put("127.0.0.1:51000"); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for a loopback caller, got %d: %s", rec.Code, rec.Body.String())
	}
	if provider.saved.CustomNetworkCIDR != "10.0.0.0/24" {
		t.Fatalf("settings not passed to the provider: %+v", provider.saved)
	}

	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "10.0.0.0/24") {
		t.Fatalf("expected the saved settings, got %d %s", rec.Code, rec.Body.String())
	}
}
