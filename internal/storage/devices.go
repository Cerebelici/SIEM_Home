package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gr0gu/cerberus/internal/identity"
	"github.com/gr0gu/cerberus/internal/model"
)

// UpsertDevice inserts a new device or updates last_seen/metadata of an existing one.
func (s *Storage) UpsertDevice(ctx context.Context, dev *model.Device) (*model.Device, bool, error) {
	return upsertDeviceInternal(ctx, s.w, dev)
}

// UpsertDevice with transaction context.
func (t *Tx) UpsertDevice(ctx context.Context, dev *model.Device) (*model.Device, bool, error) {
	return upsertDeviceInternal(ctx, t.tx, dev)
}

func upsertDeviceInternal(ctx context.Context, eq execQuerier, dev *model.Device) (*model.Device, bool, error) {
	now := time.Now().UTC()
	ip := dev.CurrentIP
	if ip == "" {
		ip = dev.IP
	}
	if ip == "" {
		return nil, false, errors.New("device current_ip is required")
	}

	var existingID int64
	var firstSeen time.Time
	var assetUID string
	var macIsRandom int
	var managed int
	var identityConfidence float64
	var label, criticality, notes string

	querySelect := `SELECT id, first_seen, asset_uid, mac_is_random, managed, identity_confidence,
		COALESCE(label, ''), criticality, COALESCE(notes, '')
		FROM devices WHERE current_ip = ? LIMIT 1;`
	err := eq.QueryRowContext(ctx, querySelect, ip).Scan(
		&existingID, &firstSeen, &assetUID, &macIsRandom, &managed, &identityConfidence,
		&label, &criticality, &notes,
	)

	normMAC := identity.NormalizeMAC(dev.MAC)
	normHost := identity.NormalizeHostname(dev.Hostname)
	isRandom := 0
	if normMAC != "" && identity.IsLocallyAdministered(normMAC) {
		isRandom = 1
	}

	if err == sql.ErrNoRows {
		status := dev.Status
		if status == "" {
			status = "up"
		}
		newAssetUID := dev.AssetUID
		if newAssetUID == "" {
			newAssetUID = uuid.NewString()
		}
		conf := dev.IdentityConfidence
		if conf == 0 {
			conf = 1.0
		}
		crit := dev.Criticality
		if crit == "" {
			crit = "normal"
		}

		insertQuery := `INSERT INTO devices (
			current_ip, mac, hostname, vendor, status, first_seen, last_seen,
			asset_uid, mac_is_random, port_profile_hash, managed, identity_confidence,
			label, criticality, notes
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', 0, ?, ?, ?, ?);`

		res, err := eq.ExecContext(ctx, insertQuery,
			ip, normMAC, normHost, dev.Vendor, status, now, now,
			newAssetUID, isRandom, conf, dev.Label, crit, dev.Notes,
		)
		if err != nil {
			return nil, false, fmt.Errorf("inserting device: %w", err)
		}

		id, _ := res.LastInsertId()
		dev.ID = id
		dev.CurrentIP = ip
		dev.IP = ip
		dev.AssetUID = newAssetUID
		dev.MACIsRandom = (isRandom == 1)
		dev.FirstSeen = now
		dev.LastSeen = now
		dev.Status = status
		dev.IdentityConfidence = conf
		dev.Criticality = crit

		// Seed open address row
		_, _ = eq.ExecContext(ctx, `INSERT INTO device_addresses (device_id, ip, mac, first_seen, last_seen, closed)
			VALUES (?, ?, ?, ?, ?, 0);`, id, ip, normMAC, now, now)

		return dev, true, nil
	} else if err != nil {
		return nil, false, fmt.Errorf("querying device by ip: %w", err)
	}

	status := dev.Status
	if status == "" {
		status = "up"
	}

	updateQuery := `UPDATE devices SET
		last_seen = ?,
		status = ?,
		mac = CASE WHEN ? != '' THEN ? ELSE mac END,
		mac_is_random = CASE WHEN ? != '' THEN ? ELSE mac_is_random END,
		hostname = CASE WHEN ? != '' THEN ? ELSE hostname END,
		vendor = CASE WHEN ? != '' THEN ? ELSE vendor END
		WHERE id = ?;`

	_, err = eq.ExecContext(ctx, updateQuery,
		now, status, normMAC, normMAC, normMAC, isRandom, normHost, normHost, dev.Vendor, dev.Vendor, existingID,
	)
	if err != nil {
		return nil, false, fmt.Errorf("updating device: %w", err)
	}

	// Update address last_seen
	_, _ = eq.ExecContext(ctx, `UPDATE device_addresses SET last_seen = ? WHERE device_id = ? AND ip = ? AND closed = 0;`,
		now, existingID, ip)

	dev.ID = existingID
	dev.CurrentIP = ip
	dev.IP = ip
	dev.AssetUID = assetUID
	dev.MACIsRandom = (macIsRandom == 1)
	dev.Managed = (managed == 1)
	dev.IdentityConfidence = identityConfidence
	dev.Label = label
	dev.Criticality = criticality
	dev.Notes = notes
	dev.FirstSeen = firstSeen
	dev.LastSeen = now
	dev.Status = status
	return dev, false, nil
}

// GetDevices returns all devices, optionally filtered by status ("up" or "down").
func (s *Storage) GetDevices(ctx context.Context, statusFilter string) ([]model.Device, error) {
	query := `SELECT d.id, d.current_ip, COALESCE(d.mac, ''), COALESCE(d.hostname, ''), COALESCE(d.vendor, ''),
		d.status, d.first_seen, d.last_seen, d.asset_uid, d.mac_is_random, COALESCE(d.port_profile_hash, ''),
		d.managed, d.identity_confidence, COALESCE(d.label, ''), d.criticality, COALESCE(d.notes, ''),
		(SELECT COUNT(*) FROM services s WHERE s.device_id = d.id AND s.state = 'open') as services_count,
		(SELECT COUNT(*) FROM vulnerabilities v WHERE v.device_id = d.id AND v.status = 'open') as vulns_count
		FROM devices d`

	var rows *sql.Rows
	var err error

	if statusFilter != "" {
		query += ` WHERE d.status = ? ORDER BY d.last_seen DESC;`
		rows, err = s.r.QueryContext(ctx, query, statusFilter)
	} else {
		query += ` ORDER BY d.last_seen DESC;`
		rows, err = s.r.QueryContext(ctx, query)
	}

	if err != nil {
		return nil, fmt.Errorf("querying devices: %w", err)
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
			&d.ServicesCount, &d.VulnerabilitiesCount,
		); err != nil {
			return nil, fmt.Errorf("scanning device row: %w", err)
		}
		d.IP = d.CurrentIP
		d.MACIsRandom = (macIsRandomInt == 1)
		d.Managed = (managedInt == 1)
		devices = append(devices, d)
	}

	return devices, nil
}

// GetDeviceByID returns a single device with all associated services and vulnerabilities.
func (s *Storage) GetDeviceByID(ctx context.Context, id int64) (*model.Device, error) {
	query := `SELECT id, current_ip, COALESCE(mac, ''), COALESCE(hostname, ''), COALESCE(vendor, ''),
		status, first_seen, last_seen, asset_uid, mac_is_random, COALESCE(port_profile_hash, ''),
		managed, identity_confidence, COALESCE(label, ''), criticality, COALESCE(notes, '')
		FROM devices WHERE id = ?;`

	var d model.Device
	var macIsRandomInt, managedInt int
	err := s.r.QueryRowContext(ctx, query, id).Scan(
		&d.ID, &d.CurrentIP, &d.MAC, &d.Hostname, &d.Vendor,
		&d.Status, &d.FirstSeen, &d.LastSeen, &d.AssetUID, &macIsRandomInt, &d.PortProfileHash,
		&managedInt, &d.IdentityConfidence, &d.Label, &d.Criticality, &d.Notes,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("querying device by id: %w", err)
	}
	d.IP = d.CurrentIP
	d.MACIsRandom = (macIsRandomInt == 1)
	d.Managed = (managedInt == 1)

	services, err := s.getServicesForDevice(ctx, d.ID, d.CurrentIP)
	if err != nil {
		return nil, err
	}
	d.Services = services
	d.ServicesCount = len(services)

	vulns, err := s.getVulnerabilitiesForDevice(ctx, d.ID, d.CurrentIP)
	if err != nil {
		return nil, err
	}
	d.Vulnerabilities = vulns
	d.VulnerabilitiesCount = len(vulns)

	return &d, nil
}

// GetDeviceByIP retrieves a device record by its IP.
func (s *Storage) GetDeviceByIP(ctx context.Context, ip string) (*model.Device, error) {
	return getDeviceByIPQuery(ctx, s.r, ip)
}

// GetDeviceByIP with transaction context.
func (t *Tx) GetDeviceByIP(ctx context.Context, ip string) (*model.Device, error) {
	return getDeviceByIPQuery(ctx, t.tx, ip)
}

func getDeviceByIPQuery(ctx context.Context, eq execQuerier, ip string) (*model.Device, error) {
	query := `SELECT id, current_ip, COALESCE(mac, ''), COALESCE(hostname, ''), COALESCE(vendor, ''),
		status, first_seen, last_seen, asset_uid, mac_is_random, COALESCE(port_profile_hash, ''),
		managed, identity_confidence, COALESCE(label, ''), criticality, COALESCE(notes, '')
		FROM devices WHERE current_ip = ? ORDER BY last_seen DESC LIMIT 1;`

	var d model.Device
	var macIsRandomInt, managedInt int
	err := eq.QueryRowContext(ctx, query, ip).Scan(
		&d.ID, &d.CurrentIP, &d.MAC, &d.Hostname, &d.Vendor,
		&d.Status, &d.FirstSeen, &d.LastSeen, &d.AssetUID, &macIsRandomInt, &d.PortProfileHash,
		&managedInt, &d.IdentityConfidence, &d.Label, &d.Criticality, &d.Notes,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("querying device by ip: %w", err)
	}
	d.IP = d.CurrentIP
	d.MACIsRandom = (macIsRandomInt == 1)
	d.Managed = (managedInt == 1)

	return &d, nil
}

// GetActiveDeviceIPs returns IPs of devices marked as 'up'.
func (s *Storage) GetActiveDeviceIPs(ctx context.Context) ([]string, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT current_ip FROM devices WHERE status = 'up' ORDER BY last_seen DESC;`)
	if err != nil {
		return nil, fmt.Errorf("querying active device IPs: %w", err)
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// MarkMissingDevicesDown marks devices absent from a discovery sweep as 'down' and writes 'down' scan records.
func (s *Storage) MarkMissingDevicesDown(ctx context.Context, scanID int64, observedDeviceIDs []int64, scanTime time.Time) error {
	if scanTime.IsZero() {
		scanTime = time.Now().UTC()
	} else {
		scanTime = scanTime.UTC()
	}

	observedMap := make(map[int64]struct{}, len(observedDeviceIDs))
	for _, id := range observedDeviceIDs {
		observedMap[id] = struct{}{}
	}

	return s.WithTx(ctx, func(tx *Tx) error {
		rows, err := tx.tx.QueryContext(ctx, `SELECT id, status FROM devices;`)
		if err != nil {
			return fmt.Errorf("querying devices for missing check: %w", err)
		}
		defer rows.Close()

		type missingDev struct {
			id    int64
			wasUp bool
		}
		var missing []missingDev

		for rows.Next() {
			var id int64
			var status string
			if err := rows.Scan(&id, &status); err != nil {
				return fmt.Errorf("scanning device: %w", err)
			}
			if _, observed := observedMap[id]; !observed {
				missing = append(missing, missingDev{id: id, wasUp: status == "up"})
			}
		}
		rows.Close()

		for _, dev := range missing {
			if dev.wasUp {
				if _, err := tx.tx.ExecContext(ctx, `UPDATE devices SET status = 'down' WHERE id = ?;`, dev.id); err != nil {
					return fmt.Errorf("updating device %d to down: %w", dev.id, err)
				}
			}

			insertRecord := `INSERT INTO device_scan_records (device_id, scan_id, status, is_vulnerable, vulns_count, max_severity, recorded_at)
				VALUES (?, ?, 'down', 0, 0, 'NONE', ?);`
			if _, err := tx.tx.ExecContext(ctx, insertRecord, dev.id, scanID, scanTime); err != nil {
				return fmt.Errorf("inserting down record for device %d: %w", dev.id, err)
			}
		}
		return nil
	})
}

// GetCandidates loads candidates seen within window for deterministic matching.
func (s *Storage) GetCandidates(ctx context.Context, window time.Duration) ([]identity.Candidate, error) {
	return getCandidatesInternal(ctx, s.r, window)
}

// GetCandidates with transaction context.
func (t *Tx) GetCandidates(ctx context.Context, window time.Duration) ([]identity.Candidate, error) {
	return getCandidatesInternal(ctx, t.tx, window)
}

func getCandidatesInternal(ctx context.Context, eq execQuerier, window time.Duration) ([]identity.Candidate, error) {
	now := time.Now().UTC()
	query := `SELECT id, asset_uid, current_ip, COALESCE(mac, ''), mac_is_random, COALESCE(hostname, ''),
		managed, identity_confidence, last_seen
		FROM devices`
	var rows *sql.Rows
	var err error
	if window > 0 {
		cutoff := now.Add(-window)
		query += ` WHERE last_seen >= ? ORDER BY last_seen DESC;`
		rows, err = eq.QueryContext(ctx, query, cutoff)
	} else {
		query += ` ORDER BY last_seen DESC;`
		rows, err = eq.QueryContext(ctx, query)
	}
	if err != nil {
		return nil, fmt.Errorf("querying candidates: %w", err)
	}
	defer rows.Close()

	var candidates []identity.Candidate
	for rows.Next() {
		var c identity.Candidate
		var macIsRand, managedInt int
		if err := rows.Scan(
			&c.ID, &c.AssetUID, &c.CurrentIP, &c.MAC, &macIsRand, &c.Hostname,
			&managedInt, &c.IdentityConfidence, &c.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("scanning candidate: %w", err)
		}
		c.MACIsRandom = (macIsRand == 1)
		c.Managed = (managedInt == 1)
		candidates = append(candidates, c)
	}
	rows.Close()

	if len(candidates) == 0 {
		return []identity.Candidate{}, nil
	}

	for i := range candidates {
		svcRows, err := eq.QueryContext(ctx, `SELECT protocol, port, COALESCE(service_name, '')
			FROM services WHERE device_id = ? AND state = 'open' ORDER BY port ASC;`, candidates[i].ID)
		if err == nil {
			for svcRows.Next() {
				var proto, name string
				var port int
				if err := svcRows.Scan(&proto, &port, &name); err == nil {
					proto = strings.ToLower(strings.TrimSpace(proto))
					if proto == "" {
						proto = "tcp"
					}
					name = strings.ToLower(strings.TrimSpace(name))
					candidates[i].Ports = append(candidates[i].Ports, fmt.Sprintf("%s/%d/%s", proto, port, name))
				}
			}
			svcRows.Close()
		}

		if candidates[i].Managed {
			var agentID string
			var lastHB sql.NullTime
			err := eq.QueryRowContext(ctx, `SELECT agent_id, last_heartbeat FROM agents WHERE device_id = ? AND status = 'active' ORDER BY last_heartbeat DESC LIMIT 1;`, candidates[i].ID).Scan(&agentID, &lastHB)
			if err == nil {
				candidates[i].BoundAgentID = agentID
				if lastHB.Valid && now.Sub(lastHB.Time) <= 90*time.Second {
					candidates[i].AgentAlive = true
				}
				ifRows, err := eq.QueryContext(ctx, `SELECT ip FROM agent_interfaces WHERE agent_id = ?;`, agentID)
				if err == nil {
					for ifRows.Next() {
						var ifIP string
						if err := ifRows.Scan(&ifIP); err == nil && ifIP != "" {
							candidates[i].AgentInterfaces = append(candidates[i].AgentInterfaces, ifIP)
						}
					}
					ifRows.Close()
				}
			}
		}
	}

	return candidates, nil
}

// ApplyDecision applies a deterministic identity decision to update or create device entities.
func (s *Storage) ApplyDecision(ctx context.Context, dec identity.Decision, obs identity.Observation) (*model.Device, error) {
	var dev *model.Device
	err := s.WithTx(ctx, func(tx *Tx) error {
		var err error
		dev, err = tx.ApplyDecision(ctx, dec, obs)
		return err
	})
	return dev, err
}

// ApplyDecision with transaction context.
func (t *Tx) ApplyDecision(ctx context.Context, dec identity.Decision, obs identity.Observation) (*model.Device, error) {
	return applyDecisionInternal(ctx, t.tx, dec, obs)
}

func applyDecisionInternal(ctx context.Context, eq execQuerier, dec identity.Decision, obs identity.Observation) (*model.Device, error) {
	observedAt := obs.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	} else {
		observedAt = observedAt.UTC()
	}

	normMAC := identity.NormalizeMAC(obs.MAC)
	normHost := identity.NormalizeHostname(obs.Hostname)
	isRandom := 0
	if normMAC != "" && identity.IsLocallyAdministered(normMAC) {
		isRandom = 1
	}

	var dev *model.Device

	switch dec.Action {
	case identity.ActionBind:
		if dec.DeviceID == nil {
			return nil, fmt.Errorf("action bind missing device_id")
		}
		targetID := *dec.DeviceID
		var d model.Device
		var macIsRandomInt, managedInt int
		querySelect := `SELECT id, current_ip, COALESCE(mac, ''), COALESCE(hostname, ''), COALESCE(vendor, ''),
			status, first_seen, last_seen, asset_uid, mac_is_random, COALESCE(port_profile_hash, ''),
			managed, identity_confidence, COALESCE(label, ''), criticality, COALESCE(notes, '')
			FROM devices WHERE id = ?;`
		err := eq.QueryRowContext(ctx, querySelect, targetID).Scan(
			&d.ID, &d.CurrentIP, &d.MAC, &d.Hostname, &d.Vendor,
			&d.Status, &d.FirstSeen, &d.LastSeen, &d.AssetUID, &macIsRandomInt, &d.PortProfileHash,
			&managedInt, &d.IdentityConfidence, &d.Label, &d.Criticality, &d.Notes,
		)
		if err != nil {
			return nil, fmt.Errorf("fetching bound device %d: %w", targetID, err)
		}
		d.IP = obs.IP
		d.CurrentIP = obs.IP
		d.LastSeen = observedAt
		d.Status = "up"
		d.Managed = (managedInt == 1)
		d.MACIsRandom = (macIsRandomInt == 1)

		if d.MAC == "" && normMAC != "" {
			d.MAC = normMAC
			d.MACIsRandom = (isRandom == 1)
		}
		if d.Hostname == "" && normHost != "" {
			d.Hostname = normHost
		}
		if dec.Confidence > d.IdentityConfidence {
			d.IdentityConfidence = dec.Confidence
		}

		macVal := d.MAC
		hostVal := d.Hostname
		macRandVal := 0
		if d.MACIsRandom {
			macRandVal = 1
		}

		updateQuery := `UPDATE devices SET
			current_ip = ?,
			last_seen = ?,
			status = 'up',
			mac = ?,
			mac_is_random = ?,
			hostname = ?,
			identity_confidence = ?
			WHERE id = ?;`
		if _, err := eq.ExecContext(ctx, updateQuery, obs.IP, observedAt, macVal, macRandVal, hostVal, d.IdentityConfidence, targetID); err != nil {
			return nil, fmt.Errorf("updating bound device: %w", err)
		}

		// Close any other device's open lease for this IP
		_, _ = eq.ExecContext(ctx, `UPDATE device_addresses SET closed = 1 WHERE ip = ? AND device_id != ? AND closed = 0;`, obs.IP, targetID)

		// Open or extend (targetID, obs.IP, normMAC)
		var addrID int64
		err = eq.QueryRowContext(ctx, `SELECT id FROM device_addresses WHERE device_id = ? AND ip = ? AND closed = 0 LIMIT 1;`, targetID, obs.IP).Scan(&addrID)
		if err == sql.ErrNoRows {
			_, _ = eq.ExecContext(ctx, `INSERT INTO device_addresses (device_id, ip, mac, first_seen, last_seen, closed)
				VALUES (?, ?, ?, ?, ?, 0);`, targetID, obs.IP, normMAC, observedAt, observedAt)
		} else if err == nil {
			_, _ = eq.ExecContext(ctx, `UPDATE device_addresses SET last_seen = ?, mac = CASE WHEN ? != '' THEN ? ELSE mac END WHERE id = ?;`,
				observedAt, normMAC, normMAC, addrID)
		}

		// Record audit row
		_, _ = eq.ExecContext(ctx, `INSERT INTO identity_decisions (
			observed_at, ip, mac, hostname, chosen_device_id, score, runner_up_device_id, runner_up_score, reason
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`,
			observedAt, obs.IP, normMAC, normHost, targetID, dec.Score, dec.RunnerUpDeviceID, dec.RunnerUpScore, dec.Reason)

		dev = &d

	case identity.ActionCreateNew, identity.ActionConflict:
		newAssetUID := uuid.NewString()
		conf := dec.Confidence
		if conf <= 0 {
			conf = 0.3
		}

		insertQuery := `INSERT INTO devices (
			current_ip, mac, hostname, vendor, status, first_seen, last_seen,
			asset_uid, mac_is_random, port_profile_hash, managed, identity_confidence,
			label, criticality, notes
		) VALUES (?, ?, ?, '', 'up', ?, ?, ?, ?, '', 0, ?, '', 'normal', '');`

		res, err := eq.ExecContext(ctx, insertQuery,
			obs.IP, normMAC, normHost, observedAt, observedAt,
			newAssetUID, isRandom, conf,
		)
		if err != nil {
			return nil, fmt.Errorf("inserting new device from decision: %w", err)
		}
		newID, _ := res.LastInsertId()

		// Close any other device's open lease for this IP
		_, _ = eq.ExecContext(ctx, `UPDATE device_addresses SET closed = 1 WHERE ip = ? AND device_id != ? AND closed = 0;`, obs.IP, newID)

		// Open lease for new device
		_, _ = eq.ExecContext(ctx, `INSERT INTO device_addresses (device_id, ip, mac, first_seen, last_seen, closed)
			VALUES (?, ?, ?, ?, ?, 0);`, newID, obs.IP, normMAC, observedAt, observedAt)

		// Record audit row
		var chosenID *int64 = &newID
		if dec.Action == identity.ActionConflict {
			chosenID = nil
		}
		_, _ = eq.ExecContext(ctx, `INSERT INTO identity_decisions (
			observed_at, ip, mac, hostname, chosen_device_id, score, runner_up_device_id, runner_up_score, reason
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`,
			observedAt, obs.IP, normMAC, normHost, chosenID, dec.Score, dec.RunnerUpDeviceID, dec.RunnerUpScore, dec.Reason)

		dev = &model.Device{
			ID:                 newID,
			CurrentIP:          obs.IP,
			IP:                 obs.IP,
			MAC:                normMAC,
			MACIsRandom:        (isRandom == 1),
			Hostname:           normHost,
			Status:             "up",
			FirstSeen:          observedAt,
			LastSeen:           observedAt,
			AssetUID:           newAssetUID,
			IdentityConfidence: conf,
			Criticality:        "normal",
		}
	}

	return dev, nil
}

// MergeDevices merges sourceID into targetID, re-parenting all children and deleting sourceID.
func (s *Storage) MergeDevices(ctx context.Context, targetID, sourceID int64) error {
	if targetID == sourceID {
		return fmt.Errorf("cannot merge device with itself")
	}

	return s.WithTx(ctx, func(tx *Tx) error {
		var targetExists int
		if err := tx.tx.QueryRowContext(ctx, `SELECT 1 FROM devices WHERE id = ?;`, targetID).Scan(&targetExists); err != nil {
			return fmt.Errorf("target device %d not found: %w", targetID, err)
		}
		var sourceManaged int
		if err := tx.tx.QueryRowContext(ctx, `SELECT managed FROM devices WHERE id = ?;`, sourceID).Scan(&sourceManaged); err != nil {
			return fmt.Errorf("source device %d not found: %w", sourceID, err)
		}

		// Re-parent services
		_, _ = tx.tx.ExecContext(ctx, `UPDATE OR IGNORE services SET device_id = ? WHERE device_id = ?;`, targetID, sourceID)
		_, _ = tx.tx.ExecContext(ctx, `DELETE FROM services WHERE device_id = ?;`, sourceID)

		// Re-parent vulnerabilities
		_, _ = tx.tx.ExecContext(ctx, `UPDATE OR IGNORE vulnerabilities SET device_id = ? WHERE device_id = ?;`, targetID, sourceID)
		_, _ = tx.tx.ExecContext(ctx, `DELETE FROM vulnerabilities WHERE device_id = ?;`, sourceID)

		// Re-parent scan records
		_, _ = tx.tx.ExecContext(ctx, `UPDATE device_scan_records SET device_id = ? WHERE device_id = ?;`, targetID, sourceID)

		// Re-parent addresses
		_, _ = tx.tx.ExecContext(ctx, `UPDATE device_addresses SET device_id = ? WHERE device_id = ?;`, targetID, sourceID)

		// Re-parent agents
		_, _ = tx.tx.ExecContext(ctx, `UPDATE agents SET device_id = ? WHERE device_id = ?;`, targetID, sourceID)

		// Re-parent incidents
		_, _ = tx.tx.ExecContext(ctx, `UPDATE incidents SET device_id = ? WHERE device_id = ?;`, targetID, sourceID)

		// Re-parent identity decisions
		_, _ = tx.tx.ExecContext(ctx, `UPDATE identity_decisions SET chosen_device_id = ? WHERE chosen_device_id = ?;`, targetID, sourceID)
		_, _ = tx.tx.ExecContext(ctx, `UPDATE identity_decisions SET runner_up_device_id = ? WHERE runner_up_device_id = ?;`, targetID, sourceID)

		// If source was managed, target becomes managed
		if sourceManaged == 1 {
			_, _ = tx.tx.ExecContext(ctx, `UPDATE devices SET managed = 1 WHERE id = ?;`, targetID)
		}

		// Delete source device
		res, err := tx.tx.ExecContext(ctx, `DELETE FROM devices WHERE id = ?;`, sourceID)
		if err != nil {
			return fmt.Errorf("deleting source device: %w", err)
		}
		rows, _ := res.RowsAffected()
		if rows == 0 {
			return sql.ErrNoRows
		}

		return nil
	})
}

// SplitDevice extracts an address lease into a newly created independent device entity.
func (s *Storage) SplitDevice(ctx context.Context, deviceID, addressID int64) (*model.Device, error) {
	var newDev *model.Device

	err := s.WithTx(ctx, func(tx *Tx) error {
		var ip, mac string
		var firstSeen, lastSeen time.Time
		err := tx.tx.QueryRowContext(ctx,
			`SELECT ip, COALESCE(mac, ''), first_seen, last_seen FROM device_addresses WHERE id = ? AND device_id = ?;`,
			addressID, deviceID,
		).Scan(&ip, &mac, &firstSeen, &lastSeen)
		if err != nil {
			if err == sql.ErrNoRows {
				return fmt.Errorf("device address %d not found on device %d", addressID, deviceID)
			}
			return fmt.Errorf("querying address: %w", err)
		}

		normMAC := identity.NormalizeMAC(mac)
		isRandom := 0
		if normMAC != "" && identity.IsLocallyAdministered(normMAC) {
			isRandom = 1
		}
		newAssetUID := uuid.NewString()

		insertQuery := `INSERT INTO devices (
			current_ip, mac, hostname, vendor, status, first_seen, last_seen,
			asset_uid, mac_is_random, port_profile_hash, managed, identity_confidence,
			label, criticality, notes
		) VALUES (?, ?, '', '', 'up', ?, ?, ?, ?, '', 0, 1.0, '', 'normal', '');`

		res, err := tx.tx.ExecContext(ctx, insertQuery, ip, normMAC, firstSeen, lastSeen, newAssetUID, isRandom)
		if err != nil {
			return fmt.Errorf("creating split device: %w", err)
		}
		newID, _ := res.LastInsertId()

		_, err = tx.tx.ExecContext(ctx, `UPDATE device_addresses SET device_id = ? WHERE id = ?;`, newID, addressID)
		if err != nil {
			return fmt.Errorf("moving address to new device: %w", err)
		}

		_, _ = tx.tx.ExecContext(ctx,
			`UPDATE agents SET device_id = ? WHERE device_id = ? AND agent_id IN (SELECT agent_id FROM agent_interfaces WHERE ip = ?);`,
			newID, deviceID, ip,
		)

		var parentCurrentIP string
		_ = tx.tx.QueryRowContext(ctx, `SELECT current_ip FROM devices WHERE id = ?;`, deviceID).Scan(&parentCurrentIP)
		if parentCurrentIP == ip {
			var fallbackIP string
			err := tx.tx.QueryRowContext(ctx,
				`SELECT ip FROM device_addresses WHERE device_id = ? AND closed = 0 ORDER BY last_seen DESC LIMIT 1;`,
				deviceID,
			).Scan(&fallbackIP)
			if err == nil && fallbackIP != "" {
				_, _ = tx.tx.ExecContext(ctx, `UPDATE devices SET current_ip = ? WHERE id = ?;`, fallbackIP, deviceID)
			}
		}

		newDev = &model.Device{
			ID:                 newID,
			CurrentIP:          ip,
			IP:                 ip,
			MAC:                normMAC,
			MACIsRandom:        (isRandom == 1),
			Status:             "up",
			FirstSeen:          firstSeen,
			LastSeen:           lastSeen,
			AssetUID:           newAssetUID,
			IdentityConfidence: 1.0,
			Criticality:        "normal",
		}

		return nil
	})

	return newDev, err
}

// DeleteDevice deletes a device and cascades deletions to related items.
func (s *Storage) DeleteDevice(ctx context.Context, id int64) error {
	res, err := s.w.ExecContext(ctx, `DELETE FROM devices WHERE id = ?;`, id)
	if err != nil {
		return fmt.Errorf("deleting device %d: %w", id, err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// UpdateDeviceFields updates label, criticality, or notes on a device.
func (s *Storage) UpdateDeviceFields(ctx context.Context, id int64, label *string, criticality *string, notes *string) (*model.Device, error) {
	if criticality != nil {
		c := strings.ToLower(strings.TrimSpace(*criticality))
		switch c {
		case "low", "normal", "high", "critical":
			*criticality = c
		default:
			return nil, fmt.Errorf("invalid criticality %q, must be low, normal, high, or critical", *criticality)
		}
	}

	query := `UPDATE devices SET
		label = COALESCE(?, label),
		criticality = COALESCE(?, criticality),
		notes = COALESCE(?, notes)
		WHERE id = ?;`

	res, err := s.w.ExecContext(ctx, query, label, criticality, notes, id)
	if err != nil {
		return nil, fmt.Errorf("updating device %d: %w", id, err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return nil, sql.ErrNoRows
	}

	return s.GetDeviceByID(ctx, id)
}

// GetDeviceIdentityDecisions retrieves the audit log of decisions for a device.
func (s *Storage) GetDeviceIdentityDecisions(ctx context.Context, deviceID int64, limit int) ([]model.IdentityDecision, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `SELECT id, observed_at, ip, COALESCE(mac, ''), COALESCE(hostname, ''),
		chosen_device_id, score, runner_up_device_id, runner_up_score, reason
		FROM identity_decisions
		WHERE chosen_device_id = ? OR runner_up_device_id = ?
		ORDER BY observed_at DESC LIMIT ?;`

	rows, err := s.r.QueryContext(ctx, query, deviceID, deviceID, limit)
	if err != nil {
		return nil, fmt.Errorf("querying identity decisions: %w", err)
	}
	defer rows.Close()

	var decisions []model.IdentityDecision
	for rows.Next() {
		var d model.IdentityDecision
		var chosenID, runnerUpID sql.NullInt64
		if err := rows.Scan(
			&d.ID, &d.ObservedAt, &d.IP, &d.MAC, &d.Hostname,
			&chosenID, &d.Score, &runnerUpID, &d.RunnerUpScore, &d.Reason,
		); err != nil {
			return nil, fmt.Errorf("scanning decision: %w", err)
		}
		if chosenID.Valid {
			d.ChosenDeviceID = &chosenID.Int64
		}
		if runnerUpID.Valid {
			d.RunnerUpDeviceID = &runnerUpID.Int64
		}
		decisions = append(decisions, d)
	}

	if decisions == nil {
		decisions = []model.IdentityDecision{}
	}
	return decisions, nil
}

// GetDeviceAddresses retrieves address lease history for a device.
func (s *Storage) GetDeviceAddresses(ctx context.Context, deviceID int64) ([]model.DeviceAddress, error) {
	query := `SELECT id, device_id, ip, COALESCE(mac, ''), first_seen, last_seen, closed
		FROM device_addresses WHERE device_id = ? ORDER BY last_seen DESC;`

	rows, err := s.r.QueryContext(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("querying device addresses: %w", err)
	}
	defer rows.Close()

	var addrs []model.DeviceAddress
	for rows.Next() {
		var a model.DeviceAddress
		var closedInt int
		if err := rows.Scan(&a.ID, &a.DeviceID, &a.IP, &a.MAC, &a.FirstSeen, &a.LastSeen, &closedInt); err != nil {
			return nil, fmt.Errorf("scanning address: %w", err)
		}
		a.Closed = (closedInt == 1)
		addrs = append(addrs, a)
	}

	if addrs == nil {
		addrs = []model.DeviceAddress{}
	}
	return addrs, nil
}

// BindAgentToDevice binds an enrolled agent to a matching device by interface IP/MAC, or creates a managed device.
func (s *Storage) BindAgentToDevice(ctx context.Context, agentID string) error {
	return s.WithTx(ctx, func(tx *Tx) error {
		ifaces, err := s.getAgentInterfaces(ctx, agentID)
		if err != nil {
			return fmt.Errorf("fetching interfaces: %w", err)
		}
		return bindAgentInternal(ctx, tx.tx, agentID, ifaces)
	})
}

func bindAgentInternal(ctx context.Context, eq execQuerier, agentID string, interfaces []model.AgentInterface) error {
	now := time.Now().UTC()

	var hostname string
	var enrolledAt time.Time
	err := eq.QueryRowContext(ctx, `SELECT hostname, enrolled_at FROM agents WHERE agent_id = ?;`, agentID).Scan(&hostname, &enrolledAt)
	if err != nil {
		return fmt.Errorf("fetching agent: %w", err)
	}

	var boundDeviceID int64
	var found bool

	for _, iface := range interfaces {
		allIPs := append([]string(nil), iface.IPv4...)
		allIPs = append(allIPs, iface.IPv6...)
		for _, ip := range allIPs {
			if ip == "" {
				continue
			}
			var devID int64
			var devMAC string
			err := eq.QueryRowContext(ctx, `SELECT id, COALESCE(mac, '') FROM devices WHERE current_ip = ?;`, ip).Scan(&devID, &devMAC)
			if err == nil {
				normIfaceMAC := identity.NormalizeMAC(iface.MAC)
				if devMAC != "" && normIfaceMAC != "" && devMAC != normIfaceMAC {
					continue
				}
				boundDeviceID = devID
				found = true
				break
			}
		}
		if found {
			break
		}
	}

	if found {
		_, err = eq.ExecContext(ctx, `UPDATE agents SET device_id = ? WHERE agent_id = ?;`, boundDeviceID, agentID)
		if err != nil {
			return fmt.Errorf("binding agent to device %d: %w", boundDeviceID, err)
		}
		_, err = eq.ExecContext(ctx, `UPDATE devices SET managed = 1 WHERE id = ?;`, boundDeviceID)
		if err != nil {
			return fmt.Errorf("marking device %d managed: %w", boundDeviceID, err)
		}
		return nil
	}

	// Create managed device from primary interface
	var primaryIP, primaryMAC string
	for _, iface := range interfaces {
		for _, ip := range iface.IPv4 {
			if ip != "" && !strings.HasPrefix(ip, "127.") {
				primaryIP = ip
				primaryMAC = identity.NormalizeMAC(iface.MAC)
				break
			}
		}
		if primaryIP != "" {
			break
		}
	}
	if primaryIP == "" && len(interfaces) > 0 {
		for _, iface := range interfaces {
			for _, ip := range iface.IPv6 {
				if ip != "" && ip != "::1" {
					primaryIP = ip
					primaryMAC = identity.NormalizeMAC(iface.MAC)
					break
				}
			}
			if primaryIP != "" {
				break
			}
		}
	}
	if primaryIP == "" {
		return nil
	}

	isRandom := 0
	if primaryMAC != "" && identity.IsLocallyAdministered(primaryMAC) {
		isRandom = 1
	}
	newAssetUID := uuid.NewString()

	insertQuery := `INSERT INTO devices (
		current_ip, mac, hostname, vendor, status, first_seen, last_seen,
		asset_uid, mac_is_random, port_profile_hash, managed, identity_confidence,
		label, criticality, notes
	) VALUES (?, ?, ?, '', 'up', ?, ?, ?, ?, '', 1, 1.0, '', 'normal', '');`

	res, err := eq.ExecContext(ctx, insertQuery, primaryIP, primaryMAC, hostname, enrolledAt, now, newAssetUID, isRandom)
	if err != nil {
		return fmt.Errorf("creating managed device for agent: %w", err)
	}
	newDevID, _ := res.LastInsertId()

	_, _ = eq.ExecContext(ctx, `UPDATE agents SET device_id = ? WHERE agent_id = ?;`, newDevID, agentID)
	_, _ = eq.ExecContext(ctx, `INSERT INTO device_addresses (device_id, ip, mac, first_seen, last_seen, closed)
		VALUES (?, ?, ?, ?, ?, 0);`, newDevID, primaryIP, primaryMAC, enrolledAt, now)

	return nil
}
