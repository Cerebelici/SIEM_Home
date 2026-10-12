package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

// SavePostureSnapshot persists a posture calculation snapshot.
func (s *Storage) SavePostureSnapshot(ctx context.Context, snap *model.PostureSnapshot) error {
	now := time.Now().UTC()
	if snap.ComputedAt.IsZero() {
		snap.ComputedAt = now
	}

	detailsJSON := snap.DetailsJSON
	if detailsJSON == "" && snap.Details != nil {
		data, err := json.Marshal(snap.Details)
		if err != nil {
			return fmt.Errorf("marshaling posture details: %w", err)
		}
		detailsJSON = string(data)
	}

	query := `INSERT INTO posture_snapshots (computed_at, policy_version, fleet_score, active_devices, details_json)
		VALUES (?, ?, ?, ?, ?);`

	res, err := s.w.ExecContext(ctx, query,
		snap.ComputedAt, snap.PolicyVersion, snap.FleetScore, snap.ActiveDevices, detailsJSON,
	)
	if err != nil {
		return fmt.Errorf("saving posture snapshot: %w", err)
	}

	id, err := res.LastInsertId()
	if err == nil {
		snap.ID = id
	}
	return nil
}

// GetLatestPostureSnapshot retrieves the most recent posture snapshot, if any.
func (s *Storage) GetLatestPostureSnapshot(ctx context.Context) (*model.PostureSnapshot, error) {
	query := `SELECT id, computed_at, policy_version, fleet_score, active_devices, details_json
		FROM posture_snapshots ORDER BY computed_at DESC LIMIT 1;`

	var snap model.PostureSnapshot
	err := s.r.QueryRowContext(ctx, query).Scan(
		&snap.ID, &snap.ComputedAt, &snap.PolicyVersion, &snap.FleetScore, &snap.ActiveDevices, &snap.DetailsJSON,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("querying latest posture snapshot: %w", err)
	}

	if snap.DetailsJSON != "" {
		var details model.PostureReport
		if err := json.Unmarshal([]byte(snap.DetailsJSON), &details); err == nil {
			snap.Details = &details
		}
	}

	return &snap, nil
}

// GetPostureHistory returns snapshots within the requested time range [from, to].
func (s *Storage) GetPostureHistory(ctx context.Context, from, to time.Time) ([]model.PostureSnapshot, error) {
	query := `SELECT id, computed_at, policy_version, fleet_score, active_devices, details_json
		FROM posture_snapshots WHERE 1=1`

	var args []any
	if !from.IsZero() {
		query += ` AND computed_at >= ?`
		args = append(args, from.UTC())
	}
	if !to.IsZero() {
		query += ` AND computed_at <= ?`
		args = append(args, to.UTC())
	}
	query += ` ORDER BY computed_at ASC;`

	rows, err := s.r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying posture history: %w", err)
	}
	defer rows.Close()

	var snapshots []model.PostureSnapshot
	for rows.Next() {
		var snap model.PostureSnapshot
		if err := rows.Scan(
			&snap.ID, &snap.ComputedAt, &snap.PolicyVersion, &snap.FleetScore, &snap.ActiveDevices, &snap.DetailsJSON,
		); err != nil {
			return nil, fmt.Errorf("scanning posture snapshot: %w", err)
		}
		if snap.DetailsJSON != "" {
			var details model.PostureReport
			if err := json.Unmarshal([]byte(snap.DetailsJSON), &details); err == nil {
				snap.Details = &details
			}
		}
		snapshots = append(snapshots, snap)
	}

	return snapshots, nil
}

// GetActiveDevicesForPosture returns devices considered active (status='up' OR last_seen >= now - activeWindow).
func (s *Storage) GetActiveDevicesForPosture(ctx context.Context, activeWindow time.Duration) ([]model.Device, error) {
	threshold := time.Now().UTC().Add(-activeWindow)

	query := `SELECT id, current_ip, COALESCE(mac, ''), COALESCE(hostname, ''), COALESCE(vendor, ''),
		status, first_seen, last_seen, asset_uid, mac_is_random, COALESCE(port_profile_hash, ''),
		managed, identity_confidence, COALESCE(label, ''), criticality, COALESCE(notes, '')
		FROM devices
		WHERE status = 'up' OR last_seen >= ?
		ORDER BY id ASC;`

	rows, err := s.r.QueryContext(ctx, query, threshold)
	if err != nil {
		return nil, fmt.Errorf("querying active devices for posture: %w", err)
	}
	defer rows.Close()

	var devices []model.Device
	for rows.Next() {
		var d model.Device
		var macIsRandomInt, managedInt int
		if err := rows.Scan(
			&d.ID, &d.CurrentIP, &d.MAC, &d.Hostname, &d.Vendor,
			&d.Status, &d.FirstSeen, &d.LastSeen, &d.AssetUID, &macIsRandomInt, &d.PortProfileHash,
			&managedInt, &d.IdentityConfidence, &d.Label, &d.Criticality, &d.Notes,
		); err != nil {
			return nil, fmt.Errorf("scanning active device: %w", err)
		}
		d.IP = d.CurrentIP
		d.MACIsRandom = (macIsRandomInt == 1)
		d.Managed = (managedInt == 1)
		devices = append(devices, d)
	}

	return devices, nil
}

// GetOpenVulnerabilitiesForDevices returns a map of open vulnerabilities keyed by device_id.
func (s *Storage) GetOpenVulnerabilitiesForDevices(ctx context.Context, deviceIDs []int64) (map[int64][]model.Vulnerability, error) {
	res := make(map[int64][]model.Vulnerability)
	if len(deviceIDs) == 0 {
		return res, nil
	}

	var placeholders []string
	var args []any
	for _, id := range deviceIDs {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}

	query := fmt.Sprintf(`SELECT id, device_id, service_port, cve_id, COALESCE(title, ''), severity, cvss_score,
		COALESCE(description, ''), COALESCE(reference_url, ''), detected_at, is_exploit, status,
		first_detected_at, last_seen_at, resolved_at
		FROM vulnerabilities
		WHERE status = 'open' AND device_id IN (%s);`, strings.Join(placeholders, ","))

	rows, err := s.r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying open vulnerabilities for devices: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var v model.Vulnerability
		var isExploitInt int
		if err := rows.Scan(
			&v.ID, &v.DeviceID, &v.ServicePort, &v.CVEID, &v.Title, &v.Severity, &v.CVSSScore,
			&v.Description, &v.ReferenceURL, &v.DetectedAt, &isExploitInt, &v.Status,
			&v.FirstDetectedAt, &v.LastSeenAt, &v.ResolvedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning vulnerability: %w", err)
		}
		v.IsExploit = (isExploitInt == 1)
		res[v.DeviceID] = append(res[v.DeviceID], v)
	}

	return res, nil
}

// GetManagedIncidentCounts returns open incident counts by severity within the specified window.
func (s *Storage) GetManagedIncidentCounts(ctx context.Context, window time.Duration) (map[string]int, error) {
	threshold := time.Now().UTC().Add(-window)

	query := `SELECT i.severity, COUNT(*)
		FROM incidents i
		LEFT JOIN devices d ON i.device_id = d.id
		WHERE (d.id IS NULL OR d.managed = 1) AND i.last_seen_at >= ?
		GROUP BY i.severity;`

	rows, err := s.r.QueryContext(ctx, query, threshold)
	if err != nil {
		return nil, fmt.Errorf("querying incident counts: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, fmt.Errorf("scanning incident count: %w", err)
		}
		counts[strings.ToUpper(sev)] = count
	}

	return counts, nil
}
