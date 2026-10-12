package storage_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/identity"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/storage"
)

func TestMigration5_TableRebuildAndChildrenPreserved(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cerberus_m5_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "v4.db")
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}

	// Create schema up to migration 4 manually
	schemaV4 := `
	CREATE TABLE devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL UNIQUE,
		mac TEXT,
		hostname TEXT,
		vendor TEXT,
		status TEXT NOT NULL DEFAULT 'up',
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL
	);
	CREATE TABLE services (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		port INTEGER NOT NULL,
		protocol TEXT NOT NULL,
		service_name TEXT,
		product TEXT,
		version TEXT,
		state TEXT NOT NULL DEFAULT 'open',
		updated_at DATETIME NOT NULL,
		last_seen_at DATETIME,
		UNIQUE(device_id, port, protocol)
	);
	CREATE TABLE vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		service_port INTEGER NOT NULL,
		cve_id TEXT NOT NULL,
		title TEXT,
		severity TEXT NOT NULL DEFAULT 'UNKNOWN',
		cvss_score REAL DEFAULT 0.0,
		description TEXT,
		reference_url TEXT,
		detected_at DATETIME NOT NULL,
		is_exploit INTEGER NOT NULL DEFAULT 0,
		exploit_refs TEXT,
		status TEXT NOT NULL DEFAULT 'open',
		first_detected_at DATETIME,
		last_seen_at DATETIME,
		resolved_at DATETIME,
		UNIQUE(device_id, service_port, cve_id)
	);
	CREATE TABLE scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_type TEXT NOT NULL,
		status TEXT NOT NULL,
		target_spec TEXT NOT NULL,
		hosts_found INTEGER DEFAULT 0,
		vulns_found INTEGER DEFAULT 0,
		duration_ms INTEGER DEFAULT 0,
		error_message TEXT,
		started_at DATETIME NOT NULL,
		completed_at DATETIME
	);
	CREATE TABLE device_scan_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
		status TEXT NOT NULL DEFAULT 'up',
		is_vulnerable INTEGER NOT NULL DEFAULT 0,
		vulns_count INTEGER NOT NULL DEFAULT 0,
		max_severity TEXT NOT NULL DEFAULT 'NONE',
		recorded_at DATETIME NOT NULL
	);
	CREATE TABLE agents (
		agent_id TEXT PRIMARY KEY,
		device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
		hostname TEXT NOT NULL,
		agent_version TEXT,
		kernel TEXT,
		token_sha256 BLOB NOT NULL,
		boot_id TEXT,
		enrolled_at DATETIME NOT NULL,
		last_heartbeat DATETIME,
		events_dropped_total INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','conflict'))
	);
	CREATE TABLE agent_interfaces (
		agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		mac TEXT,
		ip TEXT NOT NULL,
		updated_at DATETIME NOT NULL,
		PRIMARY KEY(agent_id, name, ip)
	);
	CREATE TABLE agent_batches (
		id INTEGER PRIMARY KEY,
		agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
		boot_id TEXT NOT NULL,
		seq INTEGER NOT NULL,
		received_at DATETIME NOT NULL,
		event_count INTEGER NOT NULL,
		rejected_count INTEGER NOT NULL DEFAULT 0,
		dropped_reported INTEGER NOT NULL DEFAULT 0,
		detect_pending INTEGER NOT NULL DEFAULT 1,
		UNIQUE(agent_id, boot_id, seq)
	);
	CREATE TABLE agent_events (
		id INTEGER PRIMARY KEY,
		batch_id INTEGER NOT NULL REFERENCES agent_batches(id) ON DELETE CASCADE,
		agent_id TEXT NOT NULL,
		device_id INTEGER,
		event_type TEXT NOT NULL,
		category TEXT NOT NULL,
		ts DATETIME NOT NULL,
		pid INTEGER,
		ppid INTEGER,
		uid INTEGER,
		gid INTEGER,
		comm TEXT,
		image TEXT,
		dst_ip TEXT,
		dst_port INTEGER,
		target_pid INTEGER,
		path TEXT,
		command TEXT,
		data_json TEXT NOT NULL,
		agent_rule TEXT,
		agent_severity TEXT
	);
	CREATE TABLE incidents (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
		agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
		rule_id TEXT NOT NULL,
		ruleset_version TEXT NOT NULL,
		title TEXT NOT NULL,
		severity TEXT NOT NULL,
		score REAL NOT NULL,
		mitre_tactic TEXT,
		mitre_technique TEXT,
		pid_root INTEGER,
		dedupe_key TEXT NOT NULL,
		first_seen_at DATETIME NOT NULL,
		last_seen_at DATETIME NOT NULL,
		hit_count INTEGER NOT NULL DEFAULT 1,
		evidence_event_ids TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','acknowledged','closed'))
	);

	-- Seed 3 devices with children
	INSERT INTO devices (id, ip, mac, hostname, vendor, status, first_seen, last_seen) VALUES
		(1, '192.168.1.10', '00:11:22:33:44:55', 'srv-1', 'Dell', 'up', '2026-10-10 10:00:00+00:00', '2026-10-10 12:00:00+00:00'),
		(2, '192.168.1.20', '02:aa:bb:cc:dd:ee', 'workstation', 'Lenovo', 'up', '2026-10-10 10:00:00+00:00', '2026-10-10 12:00:00+00:00'),
		(3, '192.168.1.30', '', 'printer', 'HP', 'down', '2026-10-10 10:00:00+00:00', '2026-10-10 12:00:00+00:00');

	INSERT INTO services (device_id, port, protocol, service_name, state, updated_at) VALUES
		(1, 80, 'tcp', 'http', 'open', '2026-10-10 12:00:00+00:00'),
		(1, 443, 'tcp', 'https', 'open', '2026-10-10 12:00:00+00:00'),
		(2, 22, 'tcp', 'ssh', 'open', '2026-10-10 12:00:00+00:00');

	INSERT INTO vulnerabilities (device_id, service_port, cve_id, title, severity, cvss_score, detected_at, status) VALUES
		(1, 80, 'CVE-2023-1111', 'vuln1', 'HIGH', 7.5, '2026-10-10 12:00:00+00:00', 'open'),
		(2, 22, 'CVE-2023-2222', 'vuln2', 'CRITICAL', 9.8, '2026-10-10 12:00:00+00:00', 'open');

	INSERT INTO scans (id, scan_type, status, target_spec, started_at) VALUES
		(1, 'discovery', 'completed', '192.168.1.0/24', '2026-10-10 10:00:00+00:00');

	INSERT INTO device_scan_records (device_id, scan_id, status, is_vulnerable, vulns_count, max_severity, recorded_at) VALUES
		(1, 1, 'up', 1, 1, 'HIGH', '2026-10-10 10:00:00+00:00'),
		(2, 1, 'up', 1, 1, 'CRITICAL', '2026-10-10 10:00:00+00:00');

	PRAGMA user_version = 4;
	`

	if _, err := rawDB.Exec(schemaV4); err != nil {
		rawDB.Close()
		t.Fatalf("failed to setup v4 schema fixture: %v", err)
	}
	rawDB.Close()

	// Open with storage.New, which runs migration 5
	s, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("storage.New failed with migration 5: %v", err)
	}
	defer s.Close()

	// 1. Check user_version == 5
	var ver int
	if err := s.RawReader().QueryRow("PRAGMA user_version;").Scan(&ver); err != nil {
		t.Fatal(err)
	}
	if ver != 5 {
		t.Fatalf("expected user_version=5, got %d", ver)
	}

	// 2. PRAGMA foreign_key_check empty
	fkRows, err := s.RawReader().Query("PRAGMA foreign_key_check;")
	if err != nil {
		t.Fatal(err)
	}
	defer fkRows.Close()
	if fkRows.Next() {
		var tbl, parent, fkid string
		var rowid int64
		_ = fkRows.Scan(&tbl, &rowid, &parent, &fkid)
		t.Fatalf("unexpected foreign key violation after migration 5: table %s row %d parent %s", tbl, rowid, parent)
	}

	// 3. Counts preserved
	ctx := context.Background()
	devs, err := s.GetDevices(ctx, "")
	if err != nil {
		t.Fatalf("GetDevices error: %v", err)
	}
	if len(devs) != 3 {
		t.Fatalf("expected 3 devices preserved, got %d", len(devs))
	}

	// Verify asset_uid was generated and mac_is_random correctly computed
	for _, d := range devs {
		if d.AssetUID == "" {
			t.Errorf("device %d missing generated asset_uid", d.ID)
		}
		if d.ID == 2 && !d.MACIsRandom {
			t.Errorf("device 2 with 02:aa:bb:... should have mac_is_random=true")
		}
		if d.ID == 1 && d.MACIsRandom {
			t.Errorf("device 1 with 00:11:22:... should have mac_is_random=false")
		}
	}

	// Check device_addresses seeded
	addrs, err := s.GetDeviceAddresses(ctx, 1)
	if err != nil {
		t.Fatalf("GetDeviceAddresses error: %v", err)
	}
	if len(addrs) != 1 || addrs[0].IP != "192.168.1.10" {
		t.Fatalf("expected seeded address for device 1, got %+v", addrs)
	}

	// Check services and vulns attached to device 1
	d1, err := s.GetDeviceByID(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if d1.ServicesCount != 2 {
		t.Errorf("expected 2 services for device 1, got %d", d1.ServicesCount)
	}
	if d1.VulnerabilitiesCount != 1 {
		t.Errorf("expected 1 vuln for device 1, got %d", d1.VulnerabilitiesCount)
	}
}

func TestStorage_IdentityDecisionAndDHCPMove(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC()

	// Initial device D at .10 with UAA MAC 00:11:22:33:44:55
	dec1 := identity.Decision{
		Action:     identity.ActionCreateNew,
		Confidence: 1.0,
		Reason:     "new_host",
		Score:      100.0,
	}
	obs1 := identity.Observation{
		IP:         "10.0.0.10",
		MAC:        "00:11:22:33:44:55",
		Hostname:   "laptop",
		ObservedAt: now.Add(-1 * time.Hour),
	}
	devD, err := s.ApplyDecision(ctx, dec1, obs1)
	if err != nil {
		t.Fatalf("failed to apply dec1: %v", err)
	}

	// Another device X at .23
	dec2 := identity.Decision{
		Action:     identity.ActionCreateNew,
		Confidence: 0.5,
		Reason:     "new_host",
		Score:      50.0,
	}
	obs2 := identity.Observation{
		IP:         "10.0.0.23",
		MAC:        "00:aa:bb:cc:dd:ee",
		ObservedAt: now.Add(-30 * time.Minute),
	}
	devX, err := s.ApplyDecision(ctx, dec2, obs2)
	if err != nil {
		t.Fatalf("failed to apply dec2: %v", err)
	}

	// DHCP Move: device D is seen at .23 (takes over .23, closes X's lease at .23)
	decMove := identity.Decision{
		Action:     identity.ActionBind,
		DeviceID:   &devD.ID,
		Confidence: 1.0,
		Reason:     "uaa_mac",
		Score:      100.0,
	}
	obsMove := identity.Observation{
		IP:         "10.0.0.23",
		MAC:        "00:11:22:33:44:55",
		ObservedAt: now,
	}
	updatedD, err := s.ApplyDecision(ctx, decMove, obsMove)
	if err != nil {
		t.Fatalf("failed to apply decMove: %v", err)
	}

	if updatedD.CurrentIP != "10.0.0.23" {
		t.Errorf("expected current_ip 10.0.0.23, got %s", updatedD.CurrentIP)
	}

	// Check device_addresses: X's open lease at .23 must now be closed!
	addrsX, _ := s.GetDeviceAddresses(ctx, devX.ID)
	for _, a := range addrsX {
		if a.IP == "10.0.0.23" && !a.Closed {
			t.Errorf("expected X's lease at 10.0.0.23 to be closed after D took over")
		}
	}

	// Audit decisions
	decisions, err := s.GetDeviceIdentityDecisions(ctx, devD.ID, 10)
	if err != nil {
		t.Fatalf("GetDeviceIdentityDecisions failed: %v", err)
	}
	if len(decisions) < 2 {
		t.Errorf("expected at least 2 decisions for device D, got %d", len(decisions))
	}
}

func TestStorage_MergeAndSplit(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Device 1 (Target)
	dev1, _, err := s.UpsertDevice(ctx, &model.Device{
		CurrentIP: "10.0.0.1",
		Hostname:  "host-1",
		Status:    "up",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Device 2 (Source)
	dev2, _, err := s.UpsertDevice(ctx, &model.Device{
		CurrentIP: "10.0.0.2",
		Hostname:  "host-2",
		Status:    "up",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Add service to dev2
	_, err = s.UpsertService(ctx, &model.Service{
		DeviceID: dev2.ID,
		Port:     8080,
		Protocol: "tcp",
		State:    "open",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Merge dev2 into dev1
	if err := s.MergeDevices(ctx, dev1.ID, dev2.ID); err != nil {
		t.Fatalf("MergeDevices error: %v", err)
	}

	// dev2 must be deleted
	deletedDev2, _ := s.GetDeviceByID(ctx, dev2.ID)
	if deletedDev2 != nil {
		t.Errorf("expected dev2 to be deleted after merge")
	}

	// dev1 must have the service from dev2
	dev1After, _ := s.GetDeviceByID(ctx, dev1.ID)
	if dev1After.ServicesCount != 1 {
		t.Errorf("expected dev1 to inherit service, got %d services", dev1After.ServicesCount)
	}

	// Check split
	addrs, err := s.GetDeviceAddresses(ctx, dev1.ID)
	if err != nil || len(addrs) < 2 {
		t.Fatalf("expected at least 2 addresses on dev1 after merge, got %d", len(addrs))
	}

	var addrToSplit int64
	for _, a := range addrs {
		if a.IP == "10.0.0.2" {
			addrToSplit = a.ID
			break
		}
	}
	if addrToSplit == 0 {
		t.Fatalf("did not find address 10.0.0.2 to split")
	}

	newSplitDev, err := s.SplitDevice(ctx, dev1.ID, addrToSplit)
	if err != nil {
		t.Fatalf("SplitDevice error: %v", err)
	}
	if newSplitDev.CurrentIP != "10.0.0.2" {
		t.Errorf("expected split device current_ip 10.0.0.2, got %s", newSplitDev.CurrentIP)
	}

	// Update fields
	lbl := "core-router"
	crit := "high"
	updated, err := s.UpdateDeviceFields(ctx, dev1.ID, &lbl, &crit, nil)
	if err != nil {
		t.Fatalf("UpdateDeviceFields error: %v", err)
	}
	if updated.Label != "core-router" || updated.Criticality != "high" {
		t.Errorf("unexpected updated fields: label=%s, crit=%s", updated.Label, updated.Criticality)
	}

	// Delete device
	if err := s.DeleteDevice(ctx, newSplitDev.ID); err != nil {
		t.Fatalf("DeleteDevice error: %v", err)
	}
	dCheck, _ := s.GetDeviceByID(ctx, newSplitDev.ID)
	if dCheck != nil {
		t.Errorf("expected newSplitDev to be deleted")
	}
}

func TestStorage_CloneDetection(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now().UTC()

	// Enroll agent A
	agentID := "agent-clone-test-1"
	if err := s.EnrollAgent(ctx, agentID, "host-a", []byte("hash")); err != nil {
		t.Fatal(err)
	}

	// Batch 1 from agent A with boot_id_1
	batch1 := &model.TelemetryBatch{
		SchemaVersion: 1,
		Agent: model.AgentInfo{
			AgentID:  agentID,
			BootID:   "boot-alpha",
			Hostname: "host-a",
			Interfaces: []model.AgentInterface{
				{Name: "eth0", MAC: "00:11:22:33:44:55", IPv4: []string{"192.168.1.50"}},
			},
		},
		Batch: model.BatchHeader{
			Seq:    1,
			SentAt: now,
		},
		Events: []model.RawEvent{
			{Type: "EXEC", TS: now, PID: 100, Comm: "sh", Data: []byte(`{"filename":"/bin/sh"}`)},
		},
	}
	normEvents := []model.NormalizedEvent{
		{AgentID: agentID, BootID: "boot-alpha", Type: "EXEC", Category: "process", TS: now, Comm: "sh", DataJSON: "{}"},
	}

	_, isDup, err := s.IngestBatch(ctx, batch1, normEvents, 0)
	if err != nil || isDup {
		t.Fatalf("batch1 ingest failed: err=%v, dup=%v", err, isDup)
	}

	// Batch 2 with same agent_id but DIFFERENT boot_id 10s later -> clone conflict!
	batch2 := &model.TelemetryBatch{
		SchemaVersion: 1,
		Agent: model.AgentInfo{
			AgentID:  agentID,
			BootID:   "boot-beta-conflicting",
			Hostname: "host-a-clone",
		},
		Batch: model.BatchHeader{
			Seq:    2,
			SentAt: now.Add(10 * time.Second),
		},
	}

	_, _, err = s.IngestBatch(ctx, batch2, nil, 0)
	if !errors.Is(err, storage.ErrAgentConflict) {
		t.Fatalf("expected ErrAgentConflict, got: %v", err)
	}

	// Verify agent status changed to 'conflict'
	agentRec, err := s.GetAgentByID(ctx, agentID)
	if err != nil {
		t.Fatal(err)
	}
	if agentRec.Status != "conflict" {
		t.Errorf("expected agent status 'conflict', got %s", agentRec.Status)
	}
}
