package tracker_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/tracker"
)

type mockStorage struct {
	clientID string
	calls    int
}

func (m *mockStorage) GetOrCreateClientID(ctx context.Context) (string, error) {
	m.calls++
	if m.clientID == "" {
		m.clientID = "mock-client-id-1234"
	}
	return m.clientID, nil
}

func TestTracker_PayloadFormat(t *testing.T) {
	cfg := &config.Config{
		ActiveUsersHost: "https://example.com/api/users",
		EnableTracking:  true,
		TrackingKey:     "test-key-6767",
		AppVersion:      "0.1.0",
		ClientID:        "a3bb189e-8bf9-4888-9912-ace4e6543002",
	}

	tr := tracker.New(cfg, nil)
	payload := tr.BuildPayload(context.Background())

	if payload.ClientID != "a3bb189e-8bf9-4888-9912-ace4e6543002" {
		t.Errorf("expected client_id 'a3bb189e-8bf9-4888-9912-ace4e6543002', got %s", payload.ClientID)
	}
	if payload.AppVersion != "0.1.0" {
		t.Errorf("expected app_version '0.1.0', got %s", payload.AppVersion)
	}
	if payload.OS != runtime.GOOS {
		t.Errorf("expected os '%s', got %s", runtime.GOOS, payload.OS)
	}
	if payload.Arch != runtime.GOARCH {
		t.Errorf("expected arch '%s', got %s", runtime.GOARCH, payload.Arch)
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	var rawMap map[string]interface{}
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		t.Fatalf("failed to unmarshal into map: %v", err)
	}

	expectedKeys := []string{"client_id", "app_version", "os", "arch"}
	for _, k := range expectedKeys {
		if _, ok := rawMap[k]; !ok {
			t.Errorf("expected JSON to contain key %q", k)
		}
	}
}

func TestTracker_SendSuccess(t *testing.T) {
	var receivedBody tracker.Payload
	var receivedHeaders http.Header
	var requestCount int

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		receivedHeaders = r.Header.Clone()
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
			t.Errorf("failed to decode JSON body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	cfg := &config.Config{
		ActiveUsersHost: ts.URL,
		EnableTracking:  true,
		TrackingKey:     "67676767676767676767676767",
		AppVersion:      "0.1.0",
		ClientID:        "a3bb189e-8bf9-4888-9912-ace4e6543002",
	}

	tr := tracker.New(cfg, nil)
	tr.SetHTTPClient(ts.Client())

	err := tr.Send(context.Background())
	if err != nil {
		t.Fatalf("expected successful send, got: %v", err)
	}

	if requestCount != 1 {
		t.Fatalf("expected 1 request, got %d", requestCount)
	}

	if receivedHeaders.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", receivedHeaders.Get("Content-Type"))
	}
	if receivedHeaders.Get("X-Tracking-Key") != "67676767676767676767676767" {
		t.Errorf("expected X-Tracking-Key header set, got %s", receivedHeaders.Get("X-Tracking-Key"))
	}
	if receivedHeaders.Get("Tracking-Key") != "67676767676767676767676767" {
		t.Errorf("expected Tracking-Key header set, got %s", receivedHeaders.Get("Tracking-Key"))
	}

	if receivedBody.ClientID != "a3bb189e-8bf9-4888-9912-ace4e6543002" {
		t.Errorf("expected client_id 'a3bb189e-8bf9-4888-9912-ace4e6543002', got %s", receivedBody.ClientID)
	}
	if receivedBody.AppVersion != "0.1.0" {
		t.Errorf("expected app_version '0.1.0', got %s", receivedBody.AppVersion)
	}
	if receivedBody.OS != runtime.GOOS {
		t.Errorf("expected os '%s', got %s", runtime.GOOS, receivedBody.OS)
	}
	if receivedBody.Arch != runtime.GOARCH {
		t.Errorf("expected arch '%s', got %s", runtime.GOARCH, receivedBody.Arch)
	}
}

func TestTracker_DisabledAndEmptyHost(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// 1. EnableTracking = false
	cfg1 := &config.Config{
		ActiveUsersHost: ts.URL,
		EnableTracking:  false,
		TrackingKey:     "key",
	}
	tr1 := tracker.New(cfg1, nil)
	tr1.SetHTTPClient(ts.Client())
	if err := tr1.Send(context.Background()); err != nil {
		t.Errorf("expected nil error when disabled, got %v", err)
	}
	if called {
		t.Error("HTTP server should not have been called when tracking is disabled")
	}

	// 2. ActiveUsersHost is empty
	cfg2 := &config.Config{
		ActiveUsersHost: "",
		EnableTracking:  true,
		TrackingKey:     "key",
	}
	tr2 := tracker.New(cfg2, nil)
	tr2.SetHTTPClient(ts.Client())
	if err := tr2.Send(context.Background()); err != nil {
		t.Errorf("expected nil error when host empty, got %v", err)
	}
	if called {
		t.Error("HTTP server should not have been called when host is empty")
	}
}

func TestTracker_StoragePersistence(t *testing.T) {
	mockStore := &mockStorage{clientID: "persisted-client-id"}
	cfg := &config.Config{
		ActiveUsersHost: "http://dummy",
		EnableTracking:  true,
	}

	tr := tracker.New(cfg, mockStore)
	id1 := tr.GetClientID(context.Background())
	if id1 != "persisted-client-id" {
		t.Errorf("expected 'persisted-client-id', got %s", id1)
	}

	// Second call should return cached ID without re-querying
	id2 := tr.GetClientID(context.Background())
	if id2 != "persisted-client-id" {
		t.Errorf("expected 'persisted-client-id', got %s", id2)
	}
	if mockStore.calls != 1 {
		t.Errorf("expected 1 storage call, got %d", mockStore.calls)
	}
}

func TestTracker_StartAndPeriodic(t *testing.T) {
	var requestCount atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &config.Config{
		ActiveUsersHost:  ts.URL,
		EnableTracking:   true,
		TrackingKey:      "test-key",
		TrackingInterval: 25 * time.Millisecond,
	}

	tr := tracker.New(cfg, nil)
	tr.SetHTTPClient(ts.Client())

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)

	go tr.Start(ctx, &wg)

	// Wait for at least initial ping + 1 tick
	time.Sleep(70 * time.Millisecond)

	cancel()
	wg.Wait()

	count := requestCount.Load()
	if count < 2 {
		t.Fatalf("expected at least 2 requests (initial + periodic), got %d", count)
	}
}

func TestTracker_ErrorHandling(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	cfg := &config.Config{
		ActiveUsersHost: ts.URL,
		EnableTracking:  true,
		TrackingKey:     "test-key",
	}

	tr := tracker.New(cfg, nil)
	tr.SetHTTPClient(ts.Client())

	err := tr.Send(context.Background())
	if err == nil {
		t.Fatalf("expected error on 500 response, got nil")
	}
}
