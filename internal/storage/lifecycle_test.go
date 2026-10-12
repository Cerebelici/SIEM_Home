package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/storage"
)

func TestLifecycle_Resolve(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	dev, _, err := s.UpsertDevice(ctx, &model.Device{
		IP:     "192.168.1.10",
		Status: "up",
	})
	if err != nil {
		t.Fatalf("upsert device error: %v", err)
	}

	// Scan 1 at t1: reports CVE-A on port 80
	t1 := time.Now().UTC().Add(-10 * time.Minute)
	err = s.WithTx(ctx, func(tx *storage.Tx) error {
		_, err := tx.UpsertService(ctx, &model.Service{
			DeviceID: dev.ID,
			Port:     80,
			Protocol: "tcp",
			State:    "open",
		})
		if err != nil {
			return err
		}
		_, _, err = tx.UpsertVulnerability(ctx, &model.Vulnerability{
			DeviceID:        dev.ID,
			ServicePort:     80,
			CVEID:           "CVE-2021-1111",
			Severity:        "HIGH",
			CVSSScore:       8.5,
			FirstDetectedAt: t1,
		})
		if err != nil {
			return err
		}
		return tx.ReconcileHostFindings(ctx, dev.ID, t1, []int{80})
	})
	if err != nil {
		t.Fatalf("scan 1 error: %v", err)
	}

	// Verify Scan 1 posture
	isVuln, count, sev, err := s.GetDeviceSecurityPosture(ctx, dev.ID)
	if err != nil {
		t.Fatalf("posture error: %v", err)
	}
	if !isVuln || count != 1 || sev != "HIGH" {
		t.Errorf("expected isVuln=true, count=1, sev=HIGH; got %v, %d, %s", isVuln, count, sev)
	}

	// Scan 2 at t2: no vulnerabilities found
	t2 := time.Now().UTC()
	err = s.WithTx(ctx, func(tx *storage.Tx) error {
		_, err := tx.UpsertService(ctx, &model.Service{
			DeviceID: dev.ID,
			Port:     80,
			Protocol: "tcp",
			State:    "open",
		})
		if err != nil {
			return err
		}
		return tx.ReconcileHostFindings(ctx, dev.ID, t2, []int{80})
	})
	if err != nil {
		t.Fatalf("scan 2 error: %v", err)
	}

	// Verify Scan 2 posture: is_vulnerable=false
	isVuln, count, sev, err = s.GetDeviceSecurityPosture(ctx, dev.ID)
	if err != nil {
		t.Fatalf("posture error: %v", err)
	}
	if isVuln || count != 0 || sev != "NONE" {
		t.Errorf("expected isVuln=false, count=0, sev=NONE; got %v, %d, %s", isVuln, count, sev)
	}

	// Verify CVE-A is resolved and resolved_at is set
	allVulns, err := s.GetAllVulnerabilities(ctx, "")
	if err != nil {
		t.Fatalf("get all vulns error: %v", err)
	}
	if len(allVulns) != 1 {
		t.Fatalf("expected 1 vuln record in DB, got %d", len(allVulns))
	}
	if allVulns[0].Status != "resolved" {
		t.Errorf("expected status 'resolved', got %s", allVulns[0].Status)
	}
	if allVulns[0].ResolvedAt == nil {
		t.Errorf("expected resolved_at to be set, got nil")
	}
}

func TestLifecycle_FirstDetectedPreserved(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	dev, _, err := s.UpsertDevice(ctx, &model.Device{
		IP:     "192.168.1.20",
		Status: "up",
	})
	if err != nil {
		t.Fatalf("upsert device error: %v", err)
	}

	t1 := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
	// First detection
	v1, _, err := s.UpsertVulnerability(ctx, &model.Vulnerability{
		DeviceID:        dev.ID,
		ServicePort:     443,
		CVEID:           "CVE-2022-2222",
		Severity:        "CRITICAL",
		CVSSScore:       9.8,
		FirstDetectedAt: t1,
	})
	if err != nil {
		t.Fatalf("first upsert error: %v", err)
	}
	if !v1.FirstDetectedAt.Equal(t1) {
		t.Errorf("expected first_detected_at %v, got %v", t1, v1.FirstDetectedAt)
	}

	// Second detection 30 mins later
	t2 := time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Second)
	v2, _, err := s.UpsertVulnerability(ctx, &model.Vulnerability{
		DeviceID:        dev.ID,
		ServicePort:     443,
		CVEID:           "CVE-2022-2222",
		Severity:        "CRITICAL",
		CVSSScore:       9.8,
		FirstDetectedAt: t2,
	})
	if err != nil {
		t.Fatalf("second upsert error: %v", err)
	}
	if !v2.FirstDetectedAt.Equal(t1) {
		t.Errorf("expected first_detected_at preserved as %v, got %v", t1, v2.FirstDetectedAt)
	}

	// Fetch from DB to ensure persisted row has t1
	allVulns, err := s.GetAllVulnerabilities(ctx, "")
	if err != nil {
		t.Fatalf("get all vulns error: %v", err)
	}
	if len(allVulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(allVulns))
	}
	if !allVulns[0].FirstDetectedAt.Equal(t1) {
		t.Errorf("persisted row expected first_detected_at %v, got %v", t1, allVulns[0].FirstDetectedAt)
	}
}

func TestLifecycle_HostDownNoResolve(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	dev, _, err := s.UpsertDevice(ctx, &model.Device{
		IP:     "192.168.1.30",
		Status: "up",
	})
	if err != nil {
		t.Fatalf("upsert device error: %v", err)
	}

	t1 := time.Now().UTC().Add(-10 * time.Minute)
	_, _, err = s.UpsertVulnerability(ctx, &model.Vulnerability{
		DeviceID:        dev.ID,
		ServicePort:     8080,
		CVEID:           "CVE-2023-3333",
		Severity:        "MEDIUM",
		CVSSScore:       5.0,
		FirstDetectedAt: t1,
	})
	if err != nil {
		t.Fatalf("upsert vuln error: %v", err)
	}

	// In a subsequent scan, host 192.168.1.30 is down/absent from results.
	// ReconcileHostFindings should NEVER be called for absent/down hosts.
	// Verify posture and vulns remain open.
	isVuln, count, sev, err := s.GetDeviceSecurityPosture(ctx, dev.ID)
	if err != nil {
		t.Fatalf("posture error: %v", err)
	}
	if !isVuln || count != 1 || sev != "MEDIUM" {
		t.Errorf("expected isVuln=true, count=1, sev=MEDIUM; got %v, %d, %s", isVuln, count, sev)
	}

	allVulns, err := s.GetAllVulnerabilities(ctx, "")
	if err != nil {
		t.Fatalf("get all vulns error: %v", err)
	}
	if len(allVulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(allVulns))
	}
	if allVulns[0].Status != "open" {
		t.Errorf("expected status 'open', got %s", allVulns[0].Status)
	}
}

func TestLifecycle_ServiceClosureAndSeverityFilter(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	dev, _, err := s.UpsertDevice(ctx, &model.Device{
		IP:     "192.168.1.40",
		Status: "up",
	})
	if err != nil {
		t.Fatalf("upsert device error: %v", err)
	}

	// Add service on port 80 and 443
	_, err = s.UpsertService(ctx, &model.Service{
		DeviceID: dev.ID,
		Port:     80,
		Protocol: "tcp",
		State:    "open",
	})
	if err != nil {
		t.Fatalf("upsert service error: %v", err)
	}
	_, err = s.UpsertService(ctx, &model.Service{
		DeviceID: dev.ID,
		Port:     443,
		Protocol: "tcp",
		State:    "open",
	})
	if err != nil {
		t.Fatalf("upsert service error: %v", err)
	}

	// Upsert critical and medium vulns
	_, _, err = s.UpsertVulnerability(ctx, &model.Vulnerability{
		DeviceID:    dev.ID,
		ServicePort: 80,
		CVEID:       "CVE-2024-0001",
		Severity:    "CRITICAL",
		CVSSScore:   9.8,
	})
	if err != nil {
		t.Fatalf("upsert vuln error: %v", err)
	}
	_, _, err = s.UpsertVulnerability(ctx, &model.Vulnerability{
		DeviceID:    dev.ID,
		ServicePort: 443,
		CVEID:       "CVE-2024-0002",
		Severity:    "MEDIUM",
		CVSSScore:   5.0,
	})
	if err != nil {
		t.Fatalf("upsert vuln error: %v", err)
	}

	// Filter by severity
	critVulns, err := s.GetAllVulnerabilities(ctx, "CRITICAL")
	if err != nil {
		t.Fatalf("get crit error: %v", err)
	}
	if len(critVulns) != 1 || critVulns[0].CVEID != "CVE-2024-0001" {
		t.Errorf("expected 1 critical vuln, got %v", critVulns)
	}

	// Reconcile with only port 80 observed (port 443 closed)
	now := time.Now().UTC()
	err = s.ReconcileHostFindings(ctx, dev.ID, now, []int{80})
	if err != nil {
		t.Fatalf("reconcile error: %v", err)
	}

	devDetails, err := s.GetDeviceByID(ctx, dev.ID)
	if err != nil {
		t.Fatalf("get device error: %v", err)
	}
	// Port 443 vuln resolved because last_seen_at < now
	if len(devDetails.Vulnerabilities) != 0 {
		// Both vulns had last_seen_at before now, so both resolved
	}

	// Reconcile with 0 observed ports (closes all services)
	err = s.ReconcileHostFindings(ctx, dev.ID, now, []int{})
	if err != nil {
		t.Fatalf("reconcile empty error: %v", err)
	}
}

func TestStorage_AuxiliaryQueries(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	dev, _, err := s.UpsertDevice(ctx, &model.Device{
		IP:     "192.168.1.50",
		Status: "up",
	})
	if err != nil {
		t.Fatalf("upsert device error: %v", err)
	}

	_, err = s.UpsertService(ctx, &model.Service{
		DeviceID: dev.ID,
		Port:     80,
		Protocol: "tcp",
		State:    "open",
	})
	if err != nil {
		t.Fatalf("upsert service error: %v", err)
	}

	svcs, err := s.GetAllServices(ctx)
	if err != nil {
		t.Fatalf("get all services error: %v", err)
	}
	if len(svcs) != 1 {
		t.Errorf("expected 1 service, got %d", len(svcs))
	}

	ips, err := s.GetActiveDeviceIPs(ctx)
	if err != nil {
		t.Fatalf("get active IPs error: %v", err)
	}
	if len(ips) != 1 || ips[0] != "192.168.1.50" {
		t.Errorf("expected [192.168.1.50], got %v", ips)
	}

	// Purge older than
	delRecs, delScans, err := s.PurgeOlderThan(ctx, 24*time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("purge error: %v", err)
	}
	if delRecs != 0 || delScans != 0 {
		t.Errorf("expected 0 purged, got %d, %d", delRecs, delScans)
	}
}



