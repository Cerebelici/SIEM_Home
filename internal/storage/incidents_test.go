package storage_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/storage"
)

func setupIncidentTestDB(t *testing.T) (*storage.Storage, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "incidents_test.db")

	s, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	cleanup := func() {
		_ = s.Close()
	}
	return s, cleanup
}

func TestIncidents_StorageOperations(t *testing.T) {
	s, cleanup := setupIncidentTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// 1. Create a device and enroll an agent bound to that device
	now := time.Now().UTC()
	devToInsert := &model.Device{
		IP:        "10.0.0.50",
		MAC:       "00:11:22:33:44:55",
		Hostname:  "workstation",
		Vendor:    "VendorX",
		FirstSeen: now,
		LastSeen:  now,
	}
	dev, _, err := s.UpsertDevice(ctx, devToInsert)
	if err != nil {
		t.Fatalf("failed to upsert device: %v", err)
	}

	agentID := "agent-uuid-001"
	err = s.EnrollAgent(ctx, agentID, "workstation", []byte("hash"))
	if err != nil {
		t.Fatalf("failed to enroll agent: %v", err)
	}
	_, _ = s.RawWriter().Exec("UPDATE agents SET device_id = ? WHERE agent_id = ?", dev.ID, agentID)

	// 2. Check DeviceID auto-resolution
	devIDResolved, err := s.GetDeviceIDForAgent(ctx, agentID)
	if err != nil || devIDResolved == nil || *devIDResolved != dev.ID {
		t.Fatalf("expected resolved device id %d, got %v", dev.ID, devIDResolved)
	}

	// 3. Upsert new incident
	inc := &model.Incident{
		AgentID:          agentID,
		RuleID:           "CRB-R001",
		RulesetVersion:   "1.0.0",
		Title:            "Correlated reverse shell connection",
		Severity:         "CRITICAL",
		Score:            9.5,
		MitreTactic:      "TA0011",
		MitreTechnique:   "T1059.004",
		PIDRoot:          50,
		DedupeKey:        "dedupe-1111",
		FirstSeenAt:      now,
		LastSeenAt:       now,
		HitCount:         1,
		EvidenceEventIDs: []int64{101, 102},
		Status:           "open",
	}

	saved, isNew, err := s.UpsertIncident(ctx, inc, 5*time.Minute)
	if err != nil {
		t.Fatalf("failed to upsert incident: %v", err)
	}
	if !isNew {
		t.Errorf("expected isNew=true for initial insert")
	}
	if saved.ID == 0 {
		t.Errorf("expected non-zero incident ID")
	}
	if saved.DeviceID == nil || *saved.DeviceID != dev.ID {
		t.Errorf("expected auto-resolved device id %d, got %v", dev.ID, saved.DeviceID)
	}

	// 4. Upsert with deduplication within 5 minutes
	inc2 := &model.Incident{
		AgentID:          agentID,
		RuleID:           "CRB-R001",
		DedupeKey:        "dedupe-1111",
		LastSeenAt:       now.Add(2 * time.Minute),
		EvidenceEventIDs: []int64{103},
	}
	deduped, isNew2, err := s.UpsertIncident(ctx, inc2, 5*time.Minute)
	if err != nil {
		t.Fatalf("failed to deduplicate incident: %v", err)
	}
	if isNew2 {
		t.Errorf("expected isNew=false for deduplicated incident")
	}
	if deduped.ID != saved.ID {
		t.Errorf("expected same ID %d, got %d", saved.ID, deduped.ID)
	}
	if deduped.HitCount != 2 {
		t.Errorf("expected HitCount 2, got %d", deduped.HitCount)
	}
	if len(deduped.EvidenceEventIDs) != 3 {
		t.Errorf("expected 3 merged evidence event IDs, got %d", len(deduped.EvidenceEventIDs))
	}

	// 5. Query open incidents count
	openCount, err := s.CountOpenIncidents(ctx)
	if err != nil || openCount != 1 {
		t.Errorf("expected 1 open incident, got %d (err: %v)", openCount, err)
	}

	// 6. Query list of incidents with filters
	list, err := s.GetIncidents(ctx, model.IncidentFilter{
		Status:   "open",
		Severity: "CRITICAL",
		DeviceID: &dev.ID,
	})
	if err != nil {
		t.Fatalf("failed to get incidents list: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 filtered incident, got %d", len(list))
	}

	// 7. Update incident status
	err = s.UpdateIncidentStatus(ctx, saved.ID, "acknowledged")
	if err != nil {
		t.Fatalf("failed to update incident status: %v", err)
	}

	openCountAfter, err := s.CountOpenIncidents(ctx)
	if err != nil || openCountAfter != 0 {
		t.Errorf("expected 0 open incidents after acknowledge, got %d", openCountAfter)
	}

	// 8. Fetch by ID
	fetched, err := s.GetIncidentByID(ctx, saved.ID)
	if err != nil {
		t.Fatalf("failed to fetch incident by ID: %v", err)
	}
	if fetched.Status != "acknowledged" {
		t.Errorf("expected status 'acknowledged', got '%s'", fetched.Status)
	}
}
