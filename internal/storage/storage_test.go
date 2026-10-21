package storage_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/storage"
)

func setupTestDB(t *testing.T) (*storage.Storage, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "cerberus_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	s, err := storage.New(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to create storage: %v", err)
	}

	cleanup := func() {
		_ = s.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return s, cleanup
}

func TestUpsertDevice_NewAndExisting(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// 1. Insert brand new device
	dev1 := &model.Device{
		IP:       "172.28.0.10",
		MAC:      "02:42:ac:1c:00:0a",
		Hostname: "target-nginx",
		Vendor:   "Docker",
		Status:   "up",
	}

	saved, isNew, err := s.UpsertDevice(ctx, dev1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isNew {
		t.Errorf("expected isNew=true for first-time device, got false")
	}
	if saved.ID == 0 {
		t.Errorf("expected saved.ID > 0, got %d", saved.ID)
	}

	// 2. Upsert existing device
	dev1Updated := &model.Device{
		IP:       "172.28.0.10",
		Hostname: "target-nginx-renamed",
		Status:   "up",
	}
	updated, isNew, err := s.UpsertDevice(ctx, dev1Updated)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isNew {
		t.Errorf("expected isNew=false for existing device, got true")
	}
	if updated.ID != saved.ID {
		t.Errorf("expected same device ID %d, got %d", saved.ID, updated.ID)
	}

	// Verify retrieval
	fetched, err := s.GetDeviceByID(ctx, saved.ID)
	if err != nil {
		t.Fatalf("failed to get device: %v", err)
	}
	if fetched == nil || fetched.Hostname != "target-nginx-renamed" {
		t.Errorf("expected updated hostname 'target-nginx-renamed', got %+v", fetched)
	}
	// MAC should still be preserved
	if fetched.MAC != "02:42:ac:1c:00:0a" {
		t.Errorf("expected MAC preserved '02:42:ac:1c:00:0a', got %q", fetched.MAC)
	}
}

func TestServicesAndVulnerabilities(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	dev, _, err := s.UpsertDevice(ctx, &model.Device{
		IP:     "172.28.0.30",
		Status: "up",
	})
	if err != nil {
		t.Fatalf("upsert device error: %v", err)
	}

	// Upsert Service
	svc, err := s.UpsertService(ctx, &model.Service{
		DeviceID:    dev.ID,
		Port:        80,
		Protocol:    "tcp",
		ServiceName: "http",
		Product:     "Apache httpd",
		Version:     "2.4.49",
		State:       "open",
	})
	if err != nil {
		t.Fatalf("upsert service error: %v", err)
	}
	if svc.ID == 0 {
		t.Fatalf("expected service ID > 0")
	}

	// Upsert Vulnerability
	vuln, isNewVuln, err := s.UpsertVulnerability(ctx, &model.Vulnerability{
		DeviceID:     dev.ID,
		ServicePort:  80,
		CVEID:        "CVE-2021-41773",
		Title:        "Path Traversal and File Disclosure",
		Severity:     "CRITICAL",
		CVSSScore:    9.8,
		Description:  "Path traversal vulnerability in Apache HTTP Server 2.4.49",
		ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
	})
	if err != nil {
		t.Fatalf("upsert vulnerability error: %v", err)
	}
	if !isNewVuln {
		t.Errorf("expected isNewVuln=true for first insertion")
	}
	if vuln.ID == 0 {
		t.Errorf("expected vuln ID > 0")
	}

	// Re-inserting same CVE should update, not duplicate
	_, isNewVuln2, err := s.UpsertVulnerability(ctx, &model.Vulnerability{
		DeviceID:    dev.ID,
		ServicePort: 80,
		CVEID:       "CVE-2021-41773",
		Severity:    "CRITICAL",
		CVSSScore:   9.8,
	})
	if err != nil {
		t.Fatalf("second upsert error: %v", err)
	}
	if isNewVuln2 {
		t.Errorf("expected isNewVuln2=false on duplicate")
	}

	// Check device full fetch
	devWithDetails, err := s.GetDeviceByID(ctx, dev.ID)
	if err != nil {
		t.Fatalf("get device by id error: %v", err)
	}
	if len(devWithDetails.Services) != 1 {
		t.Errorf("expected 1 service, got %d", len(devWithDetails.Services))
	}
	if len(devWithDetails.Vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(devWithDetails.Vulnerabilities))
	}

	// Check counts
	totalDevs, activeDevs, totalSvcs, totalVulns, err := s.GetCounts(ctx)
	if err != nil {
		t.Fatalf("get counts error: %v", err)
	}
	if totalDevs != 1 || activeDevs != 1 || totalSvcs != 1 || totalVulns != 1 {
		t.Errorf("unexpected counts: totalDevs=%d, activeDevs=%d, totalSvcs=%d, totalVulns=%d",
			totalDevs, activeDevs, totalSvcs, totalVulns)
	}

	// Export test
	export, err := s.ExportAllData(ctx, "172.28.0.0/24")
	if err != nil {
		t.Fatalf("export error: %v", err)
	}
	if export.TotalDevices != 1 || export.TotalVulnerabilities != 1 {
		t.Errorf("export counts mismatch: %+v", export)
	}
}

func TestScanLogWorkflow(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	log, err := s.CreateScanLog(ctx, &model.ScanLog{
		ScanType:   "discovery",
		Status:     "running",
		TargetSpec: "172.28.0.0/24",
	})
	if err != nil {
		t.Fatalf("create scan log error: %v", err)
	}
	if log.ID == 0 {
		t.Fatalf("expected log ID > 0")
	}

	// Complete scan
	log.Status = "completed"
	log.HostsFound = 3
	log.DurationMs = 1250
	time.Sleep(10 * time.Millisecond)

	err = s.UpdateScanLog(ctx, log)
	if err != nil {
		t.Fatalf("update scan log error: %v", err)
	}

	scans, err := s.GetRecentScans(ctx, 10)
	if err != nil {
		t.Fatalf("get recent scans error: %v", err)
	}
	if len(scans) != 1 || scans[0].Status != "completed" || scans[0].HostsFound != 3 {
		t.Errorf("unexpected scans: %+v", scans)
	}
}

func TestTimelineStorage(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Create a device
	dev1, _, err := s.UpsertDevice(ctx, &model.Device{
		IP:       "172.28.0.20",
		Hostname: "target-nginx",
		Status:   "up",
	})
	if err != nil {
		t.Fatalf("upsert device error: %v", err)
	}

	// 2. Create Scan 1 (Discovery) at now - 2h
	t1 := now.Add(-2 * time.Hour)
	scan1, err := s.CreateScanLog(ctx, &model.ScanLog{
		ScanType:   "discovery",
		Status:     "completed",
		TargetSpec: "172.28.0.0/24",
		HostsFound: 1,
		StartedAt:  t1,
	})
	if err != nil {
		t.Fatalf("create scan1 error: %v", err)
	}

	// Record observation for dev1 at t1 (clean / up)
	err = s.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{
		DeviceID:     dev1.ID,
		ScanID:       scan1.ID,
		Status:       "up",
		IsVulnerable: false,
		VulnsCount:   0,
		MaxSeverity:  "NONE",
		RecordedAt:   t1,
	})
	if err != nil {
		t.Fatalf("record obs1 error: %v", err)
	}

	// 3. Create Scan 2 (Vuln scan) at now - 1h
	t2 := now.Add(-1 * time.Hour)
	scan2, err := s.CreateScanLog(ctx, &model.ScanLog{
		ScanType:   "vulnerability",
		Status:     "completed",
		TargetSpec: "172.28.0.20",
		HostsFound: 1,
		VulnsFound: 1,
		StartedAt:  t2,
	})
	if err != nil {
		t.Fatalf("create scan2 error: %v", err)
	}

	// Insert vuln
	_, _, _ = s.UpsertVulnerability(ctx, &model.Vulnerability{
		DeviceID:    dev1.ID,
		ServicePort: 80,
		CVEID:       "CVE-2022-1234",
		Severity:    "HIGH",
		CVSSScore:   7.8,
	})

	isVuln, count, sev, err := s.GetDeviceSecurityPosture(ctx, dev1.ID)
	if err != nil || !isVuln || count != 1 || sev != "HIGH" {
		t.Fatalf("expected posture isVuln=true, count=1, sev=HIGH, got %v, %d, %s", isVuln, count, sev)
	}

	// Record observation for dev1 at t2 (vulnerable / up)
	err = s.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{
		DeviceID:     dev1.ID,
		ScanID:       scan2.ID,
		Status:       "up",
		IsVulnerable: isVuln,
		VulnsCount:   count,
		MaxSeverity:  sev,
		RecordedAt:   t2,
	})
	if err != nil {
		t.Fatalf("record obs2 error: %v", err)
	}

	// 4. Create Scan 3 (Discovery) at now - 30m, where dev1 is missing!
	t3 := now.Add(-30 * time.Minute)
	scan3, err := s.CreateScanLog(ctx, &model.ScanLog{
		ScanType:   "discovery",
		Status:     "completed",
		TargetSpec: "172.28.0.0/24",
		HostsFound: 0,
		StartedAt:  t3,
	})
	if err != nil {
		t.Fatalf("create scan3 error: %v", err)
	}

	// dev1 is missing
	err = s.MarkMissingDevicesDown(ctx, scan3.ID, []int64{}, t3)
	if err != nil {
		t.Fatalf("mark missing down error: %v", err)
	}

	// Verify device status is now 'down'
	dev1After, _ := s.GetDeviceByID(ctx, dev1.ID)
	if dev1After.Status != "down" {
		t.Errorf("expected device status down, got %s", dev1After.Status)
	}

	// 5. Query Timeline
	timeline, err := s.GetTimeline(ctx, now.Add(-3*time.Hour), now, "", false)
	if err != nil {
		t.Fatalf("get timeline error: %v", err)
	}

	if len(timeline.ScanTicks) != 3 {
		t.Errorf("expected 3 scan ticks, got %d", len(timeline.ScanTicks))
	}
	if len(timeline.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(timeline.Devices))
	}

	periods := timeline.Devices[0].Periods
	// Should have 3 periods:
	// 1: up, not vulnerable (NONE)
	// 2: up, vulnerable (HIGH)
	// 3: down, not vulnerable (NONE)
	if len(periods) != 3 {
		t.Fatalf("expected 3 segmented periods, got %d: %+v", len(periods), periods)
	}

	if periods[0].Status != "up" || periods[0].IsVulnerable || periods[0].MaxSeverity != "NONE" {
		t.Errorf("unexpected period 0: %+v", periods[0])
	}
	if periods[1].Status != "up" || !periods[1].IsVulnerable || periods[1].MaxSeverity != "HIGH" {
		t.Errorf("unexpected period 1: %+v", periods[1])
	}
	if periods[2].Status != "down" || periods[2].IsVulnerable {
		t.Errorf("unexpected period 2: %+v", periods[2])
	}

	// Test vulnerable_only filter
	vulnTimeline, err := s.GetTimeline(ctx, now.Add(-3*time.Hour), now, "", true)
	if err != nil {
		t.Fatalf("get vuln timeline error: %v", err)
	}
	if len(vulnTimeline.Devices) != 1 {
		t.Errorf("expected 1 device in vulnTimeline, got %d", len(vulnTimeline.Devices))
	}
}

func TestDeleteDevice_CascadeBehavior(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Create a device
	dev, _, err := s.UpsertDevice(ctx, &model.Device{
		IP:     "192.168.1.50",
		MAC:    "aa:bb:cc:dd:ee:01",
		Status: "up",
	})
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}

	// 2. Add services
	_, err = s.UpsertService(ctx, &model.Service{
		DeviceID: dev.ID, Port: 80, Protocol: "tcp", ServiceName: "http", State: "open",
	})
	if err != nil {
		t.Fatalf("upsert service 80: %v", err)
	}
	_, err = s.UpsertService(ctx, &model.Service{
		DeviceID: dev.ID, Port: 443, Protocol: "tcp", ServiceName: "https", State: "open",
	})
	if err != nil {
		t.Fatalf("upsert service 443: %v", err)
	}

	// 3. Add vulnerabilities
	_, _, err = s.UpsertVulnerability(ctx, &model.Vulnerability{
		DeviceID: dev.ID, ServicePort: 80, CVEID: "CVE-2023-1234", Severity: "HIGH", Title: "HTTP issue", DetectedAt: now,
	})
	if err != nil {
		t.Fatalf("upsert vuln 80: %v", err)
	}
	_, _, err = s.UpsertVulnerability(ctx, &model.Vulnerability{
		DeviceID: dev.ID, ServicePort: 443, CVEID: "CVE-2023-5678", Severity: "CRITICAL", Title: "SSL issue", DetectedAt: now,
	})
	if err != nil {
		t.Fatalf("upsert vuln 443: %v", err)
	}

	// 4. Create a scan and link device_scan_record
	scanLog, err := s.CreateScanLog(ctx, &model.ScanLog{
		ScanType:   "discovery",
		Status:     "completed",
		TargetSpec: "192.168.1.0/24",
		StartedAt:  now,
	})
	if err != nil {
		t.Fatalf("record scan: %v", err)
	}

	err = s.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{
		DeviceID:     dev.ID,
		ScanID:       scanLog.ID,
		Status:       "up",
		IsVulnerable: true,
		VulnsCount:   2,
		MaxSeverity:  "CRITICAL",
		RecordedAt:   now,
	})
	if err != nil {
		t.Fatalf("record device scan: %v", err)
	}

	// 5. Delete the device
	if err := s.DeleteDevice(ctx, dev.ID); err != nil {
		t.Fatalf("delete device: %v", err)
	}

	// Verify device is gone
	dCheck, _ := s.GetDeviceByID(ctx, dev.ID)
	if dCheck != nil {
		t.Errorf("expected device to be nil, got %+v", dCheck)
	}

	// Verify services were cascade deleted
	services, err := s.GetAllServices(ctx)
	if err != nil {
		t.Fatalf("get services: %v", err)
	}
	if len(services) != 0 {
		t.Errorf("expected 0 services after cascade, got %d", len(services))
	}

	// Verify vulnerabilities were cascade deleted
	vulns, err := s.GetAllVulnerabilities(ctx, "")
	if err != nil {
		t.Fatalf("get vulns: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulnerabilities after cascade, got %d", len(vulns))
	}

	// CRITICAL: Verify scans table record remains completely UNTOUCHED
	scans, err := s.GetRecentScans(ctx, 10)
	if err != nil {
		t.Fatalf("get scans: %v", err)
	}
	if len(scans) != 1 {
		t.Fatalf("expected scans table to be untouched (1 scan), got %d", len(scans))
	}
	if scans[0].ID != scanLog.ID {
		t.Errorf("expected scan id %d, got %d", scanLog.ID, scans[0].ID)
	}
}

func TestClearAllDevices_And_ClearScanHistory(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC()

	// Seed 2 devices with services and vulns
	d1, _, err := s.UpsertDevice(ctx, &model.Device{IP: "10.0.0.1", MAC: "00:11:22:33:44:01", Status: "up"})
	if err != nil {
		t.Fatalf("upsert d1: %v", err)
	}
	d2, _, err := s.UpsertDevice(ctx, &model.Device{IP: "10.0.0.2", MAC: "00:11:22:33:44:02", Status: "up"})
	if err != nil {
		t.Fatalf("upsert d2: %v", err)
	}

	_, _ = s.UpsertService(ctx, &model.Service{DeviceID: d1.ID, Port: 22, Protocol: "tcp", State: "open"})
	_, _ = s.UpsertService(ctx, &model.Service{DeviceID: d2.ID, Port: 80, Protocol: "tcp", State: "open"})
	_, _, _ = s.UpsertVulnerability(ctx, &model.Vulnerability{DeviceID: d1.ID, ServicePort: 22, CVEID: "CVE-2023-9999", Severity: "LOW", DetectedAt: now})

	// Record 2 scans
	s1, _ := s.CreateScanLog(ctx, &model.ScanLog{ScanType: "discovery", Status: "completed", StartedAt: now})
	s2, _ := s.CreateScanLog(ctx, &model.ScanLog{ScanType: "vulnerability", Status: "completed", StartedAt: now})

	_ = s.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{DeviceID: d1.ID, ScanID: s1.ID, Status: "up", RecordedAt: now})
	_ = s.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{DeviceID: d2.ID, ScanID: s2.ID, Status: "up", RecordedAt: now})

	// Test ClearAllDevices
	count, err := s.ClearAllDevices(ctx)
	if err != nil {
		t.Fatalf("ClearAllDevices error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}

	devs, _ := s.GetDevices(ctx, "")
	if len(devs) != 0 {
		t.Errorf("expected 0 devices, got %d", len(devs))
	}
	services, _ := s.GetAllServices(ctx)
	if len(services) != 0 {
		t.Errorf("expected 0 services, got %d", len(services))
	}
	vulns, _ := s.GetAllVulnerabilities(ctx, "")
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns, got %d", len(vulns))
	}

	// Scans should STILL exist!
	scans, _ := s.GetRecentScans(ctx, 10)
	if len(scans) != 2 {
		t.Fatalf("expected 2 scans preserved, got %d", len(scans))
	}

	// Now test ClearScanHistory
	scanCount, err := s.ClearScanHistory(ctx)
	if err != nil {
		t.Fatalf("ClearScanHistory error: %v", err)
	}
	if scanCount != 2 {
		t.Errorf("expected 2 scans cleared, got %d", scanCount)
	}
	scansAfter, _ := s.GetRecentScans(ctx, 10)
	if len(scansAfter) != 0 {
		t.Errorf("expected 0 scans, got %d", len(scansAfter))
	}
}

func TestDeleteService_And_Vulnerability(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC()

	dev, _, _ := s.UpsertDevice(ctx, &model.Device{IP: "192.168.1.100", Status: "up"})
	_, _ = s.UpsertService(ctx, &model.Service{
		DeviceID: dev.ID, Port: 8080, Protocol: "tcp", ServiceName: "http-proxy", State: "open",
	})
	_, _ = s.UpsertService(ctx, &model.Service{
		DeviceID: dev.ID, Port: 9090, Protocol: "tcp", ServiceName: "metrics", State: "open",
	})
	_, _, _ = s.UpsertVulnerability(ctx, &model.Vulnerability{
		DeviceID: dev.ID, ServicePort: 8080, CVEID: "CVE-2024-0001", Severity: "CRITICAL", DetectedAt: now,
	})
	_, _, _ = s.UpsertVulnerability(ctx, &model.Vulnerability{
		DeviceID: dev.ID, ServicePort: 9090, CVEID: "CVE-2024-0002", Severity: "LOW", DetectedAt: now,
	})

	services, _ := s.GetAllServices(ctx)
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}

	// Find the 8080 service ID
	var s8080ID int64
	for _, srv := range services {
		if srv.Port == 8080 {
			s8080ID = srv.ID
			break
		}
	}

	// Delete service 8080 - should also remove CVE-2024-0001
	if err := s.DeleteService(ctx, s8080ID); err != nil {
		t.Fatalf("DeleteService error: %v", err)
	}

	servicesLeft, _ := s.GetAllServices(ctx)
	if len(servicesLeft) != 1 || servicesLeft[0].Port != 9090 {
		t.Errorf("expected only port 9090 left, got %+v", servicesLeft)
	}

	vulnsLeft, _ := s.GetAllVulnerabilities(ctx, "")
	if len(vulnsLeft) != 1 || vulnsLeft[0].CVEID != "CVE-2024-0002" {
		t.Errorf("expected only CVE-2024-0002 left, got %+v", vulnsLeft)
	}

	// Now delete vulnerability directly
	if err := s.DeleteVulnerability(ctx, vulnsLeft[0].ID); err != nil {
		t.Fatalf("DeleteVulnerability error: %v", err)
	}

	vulnsFinal, _ := s.GetAllVulnerabilities(ctx, "")
	if len(vulnsFinal) != 0 {
		t.Errorf("expected 0 vulnerabilities, got %d", len(vulnsFinal))
	}
}
