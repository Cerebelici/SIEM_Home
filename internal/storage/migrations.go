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
		{
			version: 2,
			up: func(tx *sql.Tx) error {
				queries := []string{
					`ALTER TABLE vulnerabilities ADD COLUMN is_exploit INTEGER NOT NULL DEFAULT 0;`,
					`ALTER TABLE vulnerabilities ADD COLUMN exploit_refs TEXT;`,
					`ALTER TABLE vulnerabilities ADD COLUMN status TEXT NOT NULL DEFAULT 'open';`,
					`ALTER TABLE vulnerabilities ADD COLUMN first_detected_at DATETIME;`,
					`ALTER TABLE vulnerabilities ADD COLUMN last_seen_at DATETIME;`,
					`ALTER TABLE vulnerabilities ADD COLUMN resolved_at DATETIME;`,
					`UPDATE vulnerabilities SET first_detected_at = detected_at, last_seen_at = detected_at;`,
					`ALTER TABLE services ADD COLUMN last_seen_at DATETIME;`,
					`CREATE INDEX IF NOT EXISTS idx_vuln_device_status ON vulnerabilities(device_id, status);`,
					`UPDATE vulnerabilities SET severity = UPPER(severity);`,
				}
				for _, q := range queries {
					if _, err := tx.Exec(q); err != nil {
						return fmt.Errorf("executing migration 2 query (%s): %w", q, err)
					}
				}
				return nil
			},
		},
		{
			version: 3,
			up: func(tx *sql.Tx) error {
				queries := []string{
					`CREATE TABLE IF NOT EXISTS agents(
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
					);`,
					`CREATE TABLE IF NOT EXISTS agent_interfaces(
						agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
						name TEXT NOT NULL,
						mac TEXT,
						ip TEXT NOT NULL,
						updated_at DATETIME NOT NULL,
						PRIMARY KEY(agent_id, name, ip)
					);`,
					`CREATE INDEX IF NOT EXISTS idx_agent_interfaces_ip ON agent_interfaces(ip);`,
					`CREATE TABLE IF NOT EXISTS agent_batches(
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
					);`,
					`CREATE TABLE IF NOT EXISTS agent_events(
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
					);`,
					`CREATE INDEX IF NOT EXISTS idx_agent_events_agent_ts ON agent_events(agent_id, ts);`,
					`CREATE INDEX IF NOT EXISTS idx_agent_events_type_ts ON agent_events(event_type, ts);`,
					`CREATE INDEX IF NOT EXISTS idx_agent_batches_pending ON agent_batches(detect_pending) WHERE detect_pending = 1;`,
				}
				for _, q := range queries {
					if _, err := tx.Exec(q); err != nil {
						return fmt.Errorf("executing migration 3 query (%s): %w", q, err)
					}
				}
				return nil
			},
		},
		{
			version: 4,
			up: func(tx *sql.Tx) error {
				queries := []string{
					`CREATE TABLE IF NOT EXISTS incidents(
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
					);`,
					`CREATE INDEX IF NOT EXISTS idx_incidents_dedupe ON incidents(dedupe_key, last_seen_at);`,
					`CREATE INDEX IF NOT EXISTS idx_incidents_device_time ON incidents(device_id, last_seen_at);`,
					`CREATE INDEX IF NOT EXISTS idx_incidents_status_time ON incidents(status, last_seen_at);`,
				}
				for _, q := range queries {
					if _, err := tx.Exec(q); err != nil {
						return fmt.Errorf("executing migration 4 query (%s): %w", q, err)
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
