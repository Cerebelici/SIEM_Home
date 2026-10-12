package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

func TestStorage_PostureSnapshotAndHistory(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Initial latest is nil
	latest, err := s.GetLatestPostureSnapshot(ctx)
	if err != nil {
		t.Fatalf("get latest error: %v", err)
	}
	if latest != nil {
		t.Fatalf("expected nil latest, got %v", latest)
	}

	score1 := 85.5
	report1 := &model.PostureReport{
		ComputedAt:    now.Add(-10 * time.Minute),
		PolicyVersion: "cvss-agg-v1",
		FleetScore:    &score1,
		ActiveDevices: 5,
	}
	snap1 := &model.PostureSnapshot{
		ComputedAt:    now.Add(-10 * time.Minute),
		PolicyVersion: "cvss-agg-v1",
		FleetScore:    &score1,
		ActiveDevices: 5,
		Details:       report1,
	}

	if err := s.SavePostureSnapshot(ctx, snap1); err != nil {
		t.Fatalf("save snapshot 1: %v", err)
	}

	score2 := 72.0
	report2 := &model.PostureReport{
		ComputedAt:    now,
		PolicyVersion: "cvss-agg-v1",
		FleetScore:    &score2,
		ActiveDevices: 6,
	}
	snap2 := &model.PostureSnapshot{
		ComputedAt:    now,
		PolicyVersion: "cvss-agg-v1",
		FleetScore:    &score2,
		ActiveDevices: 6,
		Details:       report2,
	}

	if err := s.SavePostureSnapshot(ctx, snap2); err != nil {
		t.Fatalf("save snapshot 2: %v", err)
	}

	// Latest should be snap2
	latest, err = s.GetLatestPostureSnapshot(ctx)
	if err != nil {
		t.Fatalf("get latest error: %v", err)
	}
	if latest == nil || latest.FleetScore == nil || *latest.FleetScore != 72.0 {
		t.Fatalf("expected latest score 72.0, got %v", latest)
	}
	if latest.Details == nil || latest.Details.ActiveDevices != 6 {
		t.Fatalf("expected details populated with active_devices=6")
	}

	// History between now - 15m and now + 1m
	history, err := s.GetPostureHistory(ctx, now.Add(-15*time.Minute), now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("get history error: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 history entries, got %d", len(history))
	}

	// History with narrow window
	narrow, err := s.GetPostureHistory(ctx, now.Add(-5*time.Minute), now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("get narrow history error: %v", err)
	}
	if len(narrow) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(narrow))
	}
}

func TestStorage_PostureActiveDevicesAndVulns(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC()

	// Device 1: status="up", active
	d1, _, err := s.UpsertDevice(ctx, &model.Device{
		CurrentIP: "10.0.0.1",
		Status:    "up",
	})
	if err != nil {
		t.Fatalf("upsert d1: %v", err)
	}

	// Device 2: status="down", but seen recently (1 hour ago)
	d2, _, err := s.UpsertDevice(ctx, &model.Device{
		CurrentIP: "10.0.0.2",
		Status:    "down",
	})
	if err != nil {
		t.Fatalf("upsert d2: %v", err)
	}
	_, _ = s.RawWriter().Exec("UPDATE devices SET last_seen = ? WHERE id = ?;", now.Add(-1*time.Hour), d2.ID)

	// Device 3: status="down", seen 48 hours ago
	d3, _, err := s.UpsertDevice(ctx, &model.Device{
		CurrentIP: "10.0.0.3",
		Status:    "down",
	})
	if err != nil {
		t.Fatalf("upsert d3: %v", err)
	}
	_, _ = s.RawWriter().Exec("UPDATE devices SET last_seen = ? WHERE id = ?;", now.Add(-48*time.Hour), d3.ID)

	// Active window 24h
	activeDevs, err := s.GetActiveDevicesForPosture(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("get active devices: %v", err)
	}
	if len(activeDevs) != 2 {
		t.Fatalf("expected 2 active devices (d1 up, d2 seen 1h ago), got %d", len(activeDevs))
	}

	// Insert open and resolved vulnerabilities on d1
	_, err = s.RawWriter().Exec(`INSERT INTO vulnerabilities (
		device_id, service_port, cve_id, title, severity, cvss_score, detected_at, is_exploit, status, first_detected_at, last_seen_at
	) VALUES (?, 80, 'CVE-2023-0001', 'Test', 'HIGH', 7.5, ?, 1, 'open', ?, ?);`, d1.ID, now, now, now)
	if err != nil {
		t.Fatalf("insert vuln 1: %v", err)
	}

	_, err = s.RawWriter().Exec(`INSERT INTO vulnerabilities (
		device_id, service_port, cve_id, title, severity, cvss_score, detected_at, is_exploit, status, first_detected_at, last_seen_at
	) VALUES (?, 443, 'CVE-2023-0002', 'Test Resolved', 'MEDIUM', 5.0, ?, 0, 'resolved', ?, ?);`, d1.ID, now, now, now)
	if err != nil {
		t.Fatalf("insert vuln 2: %v", err)
	}

	vulnMap, err := s.GetOpenVulnerabilitiesForDevices(ctx, []int64{d1.ID, d2.ID})
	if err != nil {
		t.Fatalf("get open vulns: %v", err)
	}
	if len(vulnMap[d1.ID]) != 1 {
		t.Fatalf("expected 1 open vuln for d1, got %d", len(vulnMap[d1.ID]))
	}
	if vulnMap[d1.ID][0].CVEID != "CVE-2023-0001" {
		t.Errorf("expected CVE-2023-0001, got %s", vulnMap[d1.ID][0].CVEID)
	}
	if !vulnMap[d1.ID][0].IsExploit {
		t.Errorf("expected IsExploit true")
	}
}
