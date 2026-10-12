package api_test

import (
	"bytes"
	"context"
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
	"github.com/gr0gu/cerberus/internal/identity"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/scanner"
	"github.com/gr0gu/cerberus/internal/scheduler"
	"github.com/gr0gu/cerberus/internal/storage"
)

func setupDeviceAPITest(t *testing.T, apiKey string) (http.Handler, *storage.Storage, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "api_dev_test_*")
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
		APIKey:                apiKey,
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

func TestAPI_DeviceMutationAuth(t *testing.T) {
	apiKey := "secret-token-123"
	handler, store, cleanup := setupDeviceAPITest(t, apiKey)
	defer cleanup()

	ctx := context.Background()
	dev, _, err := store.UpsertDevice(ctx, &model.Device{
		CurrentIP: "10.0.0.5",
		Status:    "up",
	})
	if err != nil {
		t.Fatal(err)
	}

	patchBody := `{"label":"office-pc","criticality":"high"}`

	// 1. Non-loopback request with no API key -> 401 Unauthorized
	req1 := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/devices/%d", dev.ID), bytes.NewBufferString(patchBody))
	req1.RemoteAddr = "192.168.1.100:44321" // External IP
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized from external IP without API key, got %d", rec1.Code)
	}

	// 2. Non-loopback request with correct API key -> 200 OK
	req2 := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/devices/%d", dev.ID), bytes.NewBufferString(patchBody))
	req2.RemoteAddr = "192.168.1.100:44321"
	req2.Header.Set("X-API-Key", apiKey)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with X-API-Key, got %d: %s", rec2.Code, rec2.Body.String())
	}

	var updated model.Device
	_ = json.NewDecoder(rec2.Body).Decode(&updated)
	if updated.Label != "office-pc" || updated.Criticality != "high" {
		t.Errorf("fields not updated: label=%s, crit=%s", updated.Label, updated.Criticality)
	}

	// 3. Loopback request without API key -> 200 OK
	patchBody2 := `{"notes":"rebooted yesterday"}`
	req3 := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/devices/%d", dev.ID), bytes.NewBufferString(patchBody2))
	req3.RemoteAddr = "127.0.0.1:54321" // Loopback
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from loopback, got %d: %s", rec3.Code, rec3.Body.String())
	}
}

func TestAPI_DeviceMergeSplitDelete(t *testing.T) {
	handler, store, cleanup := setupDeviceAPITest(t, "")
	defer cleanup()

	ctx := context.Background()

	// Device 1
	d1, _, err := store.UpsertDevice(ctx, &model.Device{
		CurrentIP: "10.0.0.10",
		Hostname:  "node-1",
		Status:    "up",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Device 2
	d2, _, err := store.UpsertDevice(ctx, &model.Device{
		CurrentIP: "10.0.0.20",
		Hostname:  "node-2",
		Status:    "up",
	})
	if err != nil {
		t.Fatal(err)
	}

	// POST /api/devices/{id}/merge {source_id: d2.ID}
	mergeBody := fmt.Sprintf(`{"source_id":%d}`, d2.ID)
	reqMerge := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/devices/%d/merge", d1.ID), bytes.NewBufferString(mergeBody))
	reqMerge.RemoteAddr = "127.0.0.1:12345"
	recMerge := httptest.NewRecorder()
	handler.ServeHTTP(recMerge, reqMerge)

	if recMerge.Code != http.StatusOK {
		t.Fatalf("merge failed: code %d, body: %s", recMerge.Code, recMerge.Body.String())
	}

	// Verify GET addresses for d1
	reqAddrs := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/devices/%d/addresses", d1.ID), nil)
	recAddrs := httptest.NewRecorder()
	handler.ServeHTTP(recAddrs, reqAddrs)

	if recAddrs.Code != http.StatusOK {
		t.Fatalf("get addresses failed: %d", recAddrs.Code)
	}
	var addrsResp struct {
		Count     int                   `json:"count"`
		Addresses []model.DeviceAddress `json:"addresses"`
	}
	_ = json.NewDecoder(recAddrs.Body).Decode(&addrsResp)
	if addrsResp.Count < 2 {
		t.Fatalf("expected at least 2 addresses on d1 after merge, got %d", addrsResp.Count)
	}

	// Find the merged address to split
	var splitAddrID int64
	for _, a := range addrsResp.Addresses {
		if a.IP == "10.0.0.20" {
			splitAddrID = a.ID
			break
		}
	}
	if splitAddrID == 0 {
		t.Fatalf("could not find address 10.0.0.20 to split")
	}

	// POST /api/devices/{id}/split {address_id: splitAddrID}
	splitBody := fmt.Sprintf(`{"address_id":%d}`, splitAddrID)
	reqSplit := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/devices/%d/split", d1.ID), bytes.NewBufferString(splitBody))
	reqSplit.RemoteAddr = "127.0.0.1:12345"
	recSplit := httptest.NewRecorder()
	handler.ServeHTTP(recSplit, reqSplit)

	if recSplit.Code != http.StatusCreated {
		t.Fatalf("split failed: code %d, body: %s", recSplit.Code, recSplit.Body.String())
	}
	var splitDev model.Device
	_ = json.NewDecoder(recSplit.Body).Decode(&splitDev)
	if splitDev.CurrentIP != "10.0.0.20" {
		t.Errorf("expected split device current_ip 10.0.0.20, got %s", splitDev.CurrentIP)
	}

	// GET /api/devices/{id}/identity
	reqIdent := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/devices/%d/identity", d1.ID), nil)
	recIdent := httptest.NewRecorder()
	handler.ServeHTTP(recIdent, reqIdent)

	if recIdent.Code != http.StatusOK {
		t.Fatalf("get identity failed: %d", recIdent.Code)
	}

	// DELETE /api/devices/{id}
	reqDel := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/devices/%d", splitDev.ID), nil)
	reqDel.RemoteAddr = "127.0.0.1:12345"
	recDel := httptest.NewRecorder()
	handler.ServeHTTP(recDel, reqDel)

	if recDel.Code != http.StatusOK {
		t.Fatalf("delete device failed: %d, body: %s", recDel.Code, recDel.Body.String())
	}
}

func TestAPI_DeviceIdentityResolutionHook(t *testing.T) {
	handler, store, cleanup := setupDeviceAPITest(t, "")
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC()

	// Apply an identity decision to create device
	obs := identity.Observation{
		IP:         "192.168.1.99",
		MAC:        "00:50:56:c0:00:08",
		Hostname:   "vmware-guest",
		ObservedAt: now,
	}
	dec := identity.Decision{
		Action:     identity.ActionCreateNew,
		Confidence: 0.9,
		Reason:     "new_device",
		Score:      90.0,
	}
	dev, err := store.ApplyDecision(ctx, dec, obs)
	if err != nil {
		t.Fatal(err)
	}

	// Query identity endpoint
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/devices/%d/identity", dev.ID), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var resp struct {
		Count     int                      `json:"count"`
		Decisions []model.IdentityDecision `json:"decisions"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Count != 1 || len(resp.Decisions) != 1 {
		t.Fatalf("expected 1 decision recorded, got %d", resp.Count)
	}
	if resp.Decisions[0].Reason != "new_device" || resp.Decisions[0].Score != 90.0 {
		t.Errorf("unexpected decision content: %+v", resp.Decisions[0])
	}
}

