package storage

import (
	"database/sql"
	"fmt"
)

type migration struct {
	version int
	up      func(tx *sql.Tx) error
}

func (s *Storage) getMigrations() []migration {
	return []migration{
		{
			version: 1,
			up: func(tx *sql.Tx) error {
				queries := []string{
					`CREATE TABLE IF NOT EXISTS devices (
						id INTEGER PRIMARY KEY AUTOINCREMENT,
						ip TEXT NOT NULL UNIQUE,
						mac TEXT,
						hostname TEXT,
						vendor TEXT,
						status TEXT NOT NULL DEFAULT 'up',
						first_seen DATETIME NOT NULL,
						last_seen DATETIME NOT NULL
					);`,
					`CREATE TABLE IF NOT EXISTS services (
						id INTEGER PRIMARY KEY AUTOINCREMENT,
						device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
						port INTEGER NOT NULL,
						protocol TEXT NOT NULL,
						service_name TEXT,
						product TEXT,
						version TEXT,
						state TEXT NOT NULL DEFAULT 'open',
						updated_at DATETIME NOT NULL,
						UNIQUE(device_id, port, protocol)
					);`,
					`CREATE TABLE IF NOT EXISTS vulnerabilities (
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
						UNIQUE(device_id, service_port, cve_id)
					);`,
					`CREATE TABLE IF NOT EXISTS scans (
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
					);`,
					`CREATE TABLE IF NOT EXISTS device_scan_records (
						id INTEGER PRIMARY KEY AUTOINCREMENT,
						device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
						scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
						status TEXT NOT NULL DEFAULT 'up',
						is_vulnerable INTEGER NOT NULL DEFAULT 0,
						vulns_count INTEGER NOT NULL DEFAULT 0,
						max_severity TEXT NOT NULL DEFAULT 'NONE',
						recorded_at DATETIME NOT NULL
					);`,
					`CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);`,
					`CREATE INDEX IF NOT EXISTS idx_services_device_id ON services(device_id);`,
					`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_device_id ON vulnerabilities(device_id);`,
					`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve_id);`,
					`CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);`,
					`CREATE INDEX IF NOT EXISTS idx_device_scan_records_device ON device_scan_records(device_id, recorded_at);`,
					`CREATE INDEX IF NOT EXISTS idx_device_scan_records_scan ON device_scan_records(scan_id);`,
					`CREATE INDEX IF NOT EXISTS idx_device_scan_records_recorded_at ON device_scan_records(recorded_at);`,
				}
				for _, q := range queries {
					if _, err := tx.Exec(q); err != nil {
						return fmt.Errorf("executing migration 1 query: %w", err)
					}
				}
				return nil
			},
		},
	}
}

func (s *Storage) runMigrations() error {
	var currentVersion int
	err := s.w.QueryRow("PRAGMA user_version;").Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("reading user_version: %w", err)
	}

	for _, m := range s.getMigrations() {
		if m.version > currentVersion {
			tx, err := s.w.Begin()
			if err != nil {
				return fmt.Errorf("begin migration %d: %w", m.version, err)
			}
			if err := m.up(tx); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("running migration %d: %w", m.version, err)
			}
			if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d;", m.version)); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("setting user_version = %d: %w", m.version, err)
			}
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("committing migration %d: %w", m.version, err)
			}
		}
	}
	return nil
}
