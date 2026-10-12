package posture

import (
	"context"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

type mockPostureStore struct {
	devices        []model.Device
	vulns          map[int64][]model.Vulnerability
	incidents      map[string]int
	savedSnapshots []*model.PostureSnapshot
	history        []model.PostureSnapshot
	getDevicesCalls int
}

func (m *mockPostureStore) GetActiveDevicesForPosture(ctx context.Context, activeWindow time.Duration) ([]model.Device, error) {
	m.getDevicesCalls++
	return m.devices, nil
}

func (m *mockPostureStore) GetOpenVulnerabilitiesForDevices(ctx context.Context, deviceIDs []int64) (map[int64][]model.Vulnerability, error) {
	return m.vulns, nil
}

func (m *mockPostureStore) GetManagedIncidentCounts(ctx context.Context, window time.Duration) (map[string]int, error) {
	return m.incidents, nil
}

func (m *mockPostureStore) SavePostureSnapshot(ctx context.Context, snap *model.PostureSnapshot) error {
	m.savedSnapshots = append(m.savedSnapshots, snap)
	return nil
}

func (m *mockPostureStore) GetLatestPostureSnapshot(ctx context.Context) (*model.PostureSnapshot, error) {
	if len(m.savedSnapshots) == 0 {
		return nil, nil
	}
	return m.savedSnapshots[len(m.savedSnapshots)-1], nil
}

func (m *mockPostureStore) GetPostureHistory(ctx context.Context, from, to time.Time) ([]model.PostureSnapshot, error) {
	return m.history, nil
}

func TestService_ComputeAndCache(t *testing.T) {
	store := &mockPostureStore{
		devices: []model.Device{
			{ID: 1, CurrentIP: "10.0.0.1", Hostname: "host-a", Status: "up"},
			{ID: 2, CurrentIP: "10.0.0.2", Hostname: "host-b", Status: "up"},
		},
		vulns: map[int64][]model.Vulnerability{
			1: {
				{CVEID: "CVE-2023-1", CVSSScore: 9.8, Status: "open"},
			},
			2: {
				{CVEID: "CVE-2023-2", CVSSScore: 5.0, Status: "open"},
				{CVEID: "CVE-2023-3", CVSSScore: 8.0, Status: "resolved"}, // Should be ignored
			},
		},
		incidents: map[string]int{
			"HIGH": 1,
		},
	}

	svc := NewService(store, DefaultPolicy)
	ctx := context.Background()

	// 1. First compute (fresh)
	report1, err := svc.Compute(ctx)
	if err != nil {
		t.Fatalf("compute error: %v", err)
	}
	if report1.ActiveDevices != 2 {
		t.Errorf("expected 2 active devices, got %d", report1.ActiveDevices)
	}
	if report1.FleetScore == nil {
		t.Fatalf("expected non-nil fleet score")
	}
	if store.getDevicesCalls != 1 {
		t.Errorf("expected 1 getDevices call, got %d", store.getDevicesCalls)
	}

	// 2. Second compute (cached)
	report2, err := svc.Compute(ctx)
	if err != nil {
		t.Fatalf("compute error: %v", err)
	}
	if *report2.FleetScore != *report1.FleetScore {
		t.Errorf("expected identical cached score")
	}
	if store.getDevicesCalls != 1 {
		t.Errorf("expected still 1 getDevices call due to caching, got %d", store.getDevicesCalls)
	}

	// 3. Invalidate cache
	svc.InvalidateCache()
	_, err = svc.Compute(ctx)
	if err != nil {
		t.Fatalf("compute error: %v", err)
	}
	if store.getDevicesCalls != 2 {
		t.Errorf("expected 2 getDevices calls after invalidate, got %d", store.getDevicesCalls)
	}
}

func TestService_EmptyFleet(t *testing.T) {
	store := &mockPostureStore{
		devices: nil,
	}

	svc := NewService(store, DefaultPolicy)
	report, err := svc.Compute(context.Background())
	if err != nil {
		t.Fatalf("compute error: %v", err)
	}
	if report.ActiveDevices != 0 {
		t.Errorf("expected 0 active devices, got %d", report.ActiveDevices)
	}
	if report.FleetScore != nil {
		t.Errorf("expected nil fleet score, got %v", report.FleetScore)
	}
	if report.PostureStatus != "no_assets" {
		t.Errorf("expected posture status 'no_assets', got %s", report.PostureStatus)
	}
}

func TestService_SnapshotAndHistory(t *testing.T) {
	store := &mockPostureStore{
		devices: []model.Device{
			{ID: 1, CurrentIP: "10.0.0.1", Status: "up"},
		},
		vulns: map[int64][]model.Vulnerability{
			1: {{CVEID: "CVE-2023-1", CVSSScore: 7.0, Status: "open"}},
		},
	}

	svc := NewService(store, DefaultPolicy)
	ctx := context.Background()

	snap, err := svc.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap == nil || snap.FleetScore == nil {
		t.Fatalf("expected valid snapshot")
	}
	if len(store.savedSnapshots) != 1 {
		t.Fatalf("expected 1 saved snapshot, got %d", len(store.savedSnapshots))
	}

	history, err := svc.GetHistory(ctx, time.Now().Add(-1*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("get history error: %v", err)
	}
	_ = history
}
