package storage_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/storage"
)

func assertStoredUTC(t *testing.T, s *storage.Storage, table, col string) {
	t.Helper()
	rows, err := s.RawReader().Query(fmt.Sprintf("SELECT %s FROM %s LIMIT 5;", col, table))
	if err != nil {
		t.Fatalf("querying raw string for %s.%s: %v", table, col, err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatalf("scanning raw string: %v", err)
		}
		count++
		if !strings.HasSuffix(raw, "+00:00") && !strings.HasSuffix(raw, "Z") {
			t.Errorf("stored %s.%s value %q does not end with UTC suffix (+00:00 or Z)", table, col, raw)
		}
	}
	if count == 0 {
		t.Errorf("no rows found for %s.%s", table, col)
	}
}

func TestTimeline_NonUTCHost(t *testing.T) {
	origLocal := time.Local
	defer func() { time.Local = origLocal }()
	time.Local = time.FixedZone("EEST", 3*3600)

	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	dev, _, err := s.UpsertDevice(ctx, &model.Device{IP: "192.168.1.100", Status: "up"})
	if err != nil {
		t.Fatalf("upsert device error: %v", err)
	}

	now := time.Now() // local +3h
	scanLog, err := s.CreateScanLog(ctx, &model.ScanLog{
		ScanType:  "discovery",
		Status:    "completed",
		StartedAt: now,
	})
	if err != nil {
		t.Fatalf("create scan log error: %v", err)
	}

	err = s.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{
		DeviceID:   dev.ID,
		ScanID:     scanLog.ID,
		Status:     "up",
		RecordedAt: now,
	})
	if err != nil {
		t.Fatalf("record observation error: %v", err)
	}

	// Query in UTC window
	fromUTC := time.Now().UTC().Add(-10 * time.Minute)
	toUTC := time.Now().UTC().Add(10 * time.Minute)
	timeline, err := s.GetTimeline(ctx, fromUTC, toUTC, "", false)
	if err != nil {
		t.Fatalf("get timeline error: %v", err)
	}
	if len(timeline.Devices) == 0 {
		t.Fatalf("expected device in timeline, got 0 devices")
	}
	if len(timeline.Devices[0].Periods) == 0 {
		t.Fatalf("expected at least 1 period in timeline, got 0")
	}
	if timeline.Devices[0].Periods[0].Status != "up" {
		t.Errorf("expected period status 'up', got '%s'", timeline.Devices[0].Periods[0].Status)
	}

	// Assert stored strings end in +00:00 or Z
	assertStoredUTC(t, s, "device_scan_records", "recorded_at")
	assertStoredUTC(t, s, "devices", "first_seen")
	assertStoredUTC(t, s, "devices", "last_seen")
	assertStoredUTC(t, s, "scans", "started_at")
}

func TestTimeline_CarryIn(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	dev, _, err := s.UpsertDevice(ctx, &model.Device{IP: "192.168.1.101", Status: "down"})
	if err != nil {
		t.Fatalf("upsert device error: %v", err)
	}

	now := time.Now().UTC()
	from := now.Add(-2 * time.Hour)
	to := now.Add(-1 * time.Hour)
	recordTime := from.Add(-1 * time.Hour) // from - 1h

	scanLog, err := s.CreateScanLog(ctx, &model.ScanLog{
		ScanType:  "discovery",
		Status:    "completed",
		StartedAt: recordTime,
	})
	if err != nil {
		t.Fatalf("create scan log: %v", err)
	}

	err = s.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{
		DeviceID:   dev.ID,
		ScanID:     scanLog.ID,
		Status:     "down",
		RecordedAt: recordTime,
	})
	if err != nil {
		t.Fatalf("record observation error: %v", err)
	}

	timeline, err := s.GetTimeline(ctx, from, to, "", false)
	if err != nil {
		t.Fatalf("get timeline: %v", err)
	}
	if len(timeline.Devices) == 0 {
		t.Fatalf("expected device in timeline, got 0")
	}
	periods := timeline.Devices[0].Periods
	if len(periods) != 1 {
		t.Fatalf("expected exactly 1 carry-in period, got %d", len(periods))
	}
	p := periods[0]
	if p.Status != "down" {
		t.Errorf("expected status 'down', got %s", p.Status)
	}
	if !p.StartedAt.Equal(from) {
		t.Errorf("expected StartedAt equal to from (%v), got %v", from, p.StartedAt)
	}
	if !p.EndedAt.Equal(to) {
		t.Errorf("expected EndedAt equal to to (%v), got %v", to, p.EndedAt)
	}
}

func TestTimeline_NoGaps(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	dev, _, _ := s.UpsertDevice(ctx, &model.Device{IP: "192.168.1.102", Status: "up"})

	t0 := time.Now().UTC().Add(-4 * time.Hour)
	t1 := t0.Add(1 * time.Hour)
	t2 := t0.Add(2 * time.Hour)
	t3 := t0.Add(3 * time.Hour)

	scan1, _ := s.CreateScanLog(ctx, &model.ScanLog{ScanType: "discovery", Status: "completed", StartedAt: t0})
	scan2, _ := s.CreateScanLog(ctx, &model.ScanLog{ScanType: "discovery", Status: "completed", StartedAt: t1})
	scan3, _ := s.CreateScanLog(ctx, &model.ScanLog{ScanType: "discovery", Status: "completed", StartedAt: t2})

	_ = s.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{DeviceID: dev.ID, ScanID: scan1.ID, Status: "up", RecordedAt: t0})
	_ = s.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{DeviceID: dev.ID, ScanID: scan2.ID, Status: "down", RecordedAt: t1})
	_ = s.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{DeviceID: dev.ID, ScanID: scan3.ID, Status: "up", RecordedAt: t2})

	timeline, err := s.GetTimeline(ctx, t0, t3, "", false)
	if err != nil {
		t.Fatalf("get timeline: %v", err)
	}
	if len(timeline.Devices) == 0 {
		t.Fatalf("expected device in timeline, got 0")
	}
	periods := timeline.Devices[0].Periods
	if len(periods) < 2 {
		t.Fatalf("expected at least 2 periods, got %d", len(periods))
	}

	for k := 0; k < len(periods)-1; k++ {
		if !periods[k].EndedAt.Equal(periods[k+1].StartedAt) {
			t.Errorf("gap detected between period %d and %d: ended %v != started %v",
				k, k+1, periods[k].EndedAt, periods[k+1].StartedAt)
		}
	}
}

func TestTimeline_HistoricalNotOngoing(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	dev, _, _ := s.UpsertDevice(ctx, &model.Device{IP: "192.168.1.103", Status: "up"})

	sevenDaysAgo := time.Now().UTC().Add(-7 * 24 * time.Hour)
	from := sevenDaysAgo.Add(-2 * time.Hour)
	to := sevenDaysAgo

	scan, _ := s.CreateScanLog(ctx, &model.ScanLog{ScanType: "discovery", Status: "completed", StartedAt: from})
	_ = s.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{DeviceID: dev.ID, ScanID: scan.ID, Status: "up", RecordedAt: from})

	timeline, err := s.GetTimeline(ctx, from, to, "", false)
	if err != nil {
		t.Fatalf("get timeline: %v", err)
	}
	for _, devTimeline := range timeline.Devices {
		for _, p := range devTimeline.Periods {
			if p.IsOngoing {
				t.Errorf("historical period should NOT be ongoing: %+v", p)
			}
		}
	}
}

func TestMigrations_FromV0(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cerberus_v0_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "v0.db")

	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	v0Schema := `
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
		INSERT INTO devices (ip, status, first_seen, last_seen)
		VALUES ('10.0.0.1', 'up', '2026-01-01 00:00:00+00:00', '2026-01-01 00:00:00+00:00');
		PRAGMA user_version = 0;
	`
	if _, err := rawDB.Exec(v0Schema); err != nil {
		rawDB.Close()
		t.Fatal(err)
	}
	rawDB.Close()

	s, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("failed to open storage from v0 DB: %v", err)
	}
	defer s.Close()

	var version int
	if err := s.RawReader().QueryRow("PRAGMA user_version;").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 4 {
		t.Errorf("expected user_version=4, got %d", version)
	}

	dev, err := s.GetDeviceByIP(context.Background(), "10.0.0.1")
	if err != nil || dev == nil {
		t.Fatalf("expected device 10.0.0.1 to be preserved: %v", err)
	}
}

func TestMain_NoSeedByDefault(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	totalDevs, _, _, _, err := s.GetCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if totalDevs != 0 {
		t.Errorf("expected 0 devices by default in fresh DB, got %d", totalDevs)
	}
}

func TestConcurrent_ReadersAndWriter(t *testing.T) {
	s, cleanup := setupTestDB(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	readers := 4

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(rID int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					_, err := s.GetDevices(ctx, "")
					if err != nil && !errors.Is(err, context.Canceled) {
						t.Errorf("reader %d failed: %v", rID, err)
						return
					}
				}
			}
		}(i)
	}

	const rowCount = 10000
	err := s.WithTx(ctx, func(tx *storage.Tx) error {
		for i := 0; i < rowCount; i++ {
			ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
			_, _, err := tx.UpsertDevice(ctx, &model.Device{
				IP:     ip,
				Status: "up",
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("writer failed: %v", err)
	}

	cancel()
	wg.Wait()
}
