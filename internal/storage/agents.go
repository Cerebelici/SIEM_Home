package storage

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

// EnrollAgent registers an agent or updates its token upon re-enrollment.
func (s *Storage) EnrollAgent(ctx context.Context, agentID, hostname string, tokenSHA256 []byte) error {
	now := time.Now().UTC()
	query := `INSERT INTO agents (agent_id, hostname, token_sha256, enrolled_at, status)
		VALUES (?, ?, ?, ?, 'active')
		ON CONFLICT(agent_id) DO UPDATE SET
			hostname = excluded.hostname,
			token_sha256 = excluded.token_sha256,
			status = 'active',
			enrolled_at = excluded.enrolled_at;`

	_, err := s.w.ExecContext(ctx, query, agentID, hostname, tokenSHA256, now)
	if err != nil {
		return fmt.Errorf("enrolling agent %s: %w", agentID, err)
	}
	return nil
}

// GetAgentAuth retrieves the SHA-256 token hash and status for an agent.
func (s *Storage) GetAgentAuth(ctx context.Context, agentID string) ([]byte, string, error) {
	query := `SELECT token_sha256, status FROM agents WHERE agent_id = ?;`
	var tokenHash []byte
	var status string
	err := s.r.QueryRowContext(ctx, query, agentID).Scan(&tokenHash, &status)
	if err != nil {
		return nil, "", err
	}
	return tokenHash, status, nil
}

// GetAgents lists all enrolled agents.
func (s *Storage) GetAgents(ctx context.Context) ([]model.AgentRecord, error) {
	query := `SELECT agent_id, device_id, hostname, COALESCE(agent_version, ''), COALESCE(kernel, ''),
		COALESCE(boot_id, ''), enrolled_at, last_heartbeat, events_dropped_total, status
		FROM agents ORDER BY enrolled_at DESC;`

	rows, err := s.r.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("querying agents: %w", err)
	}
	defer rows.Close()

	var agents []model.AgentRecord
	for rows.Next() {
		var a model.AgentRecord
		var devID sql.NullInt64
		var lastHB sql.NullTime

		if err := rows.Scan(
			&a.AgentID, &devID, &a.Hostname, &a.AgentVersion, &a.Kernel,
			&a.BootID, &a.EnrolledAt, &lastHB, &a.EventsDroppedTotal, &a.Status,
		); err != nil {
			return nil, err
		}
		if devID.Valid {
			a.DeviceID = &devID.Int64
		}
		if lastHB.Valid {
			a.LastHeartbeat = &lastHB.Time
		}
		agents = append(agents, a)
	}

	for i := range agents {
		ifaces, err := s.getAgentInterfaces(ctx, agents[i].AgentID)
		if err == nil {
			agents[i].Interfaces = ifaces
		}
	}

	return agents, nil
}

// GetAgentByID returns a single agent by its unique identifier.
func (s *Storage) GetAgentByID(ctx context.Context, agentID string) (*model.AgentRecord, error) {
	query := `SELECT agent_id, device_id, hostname, COALESCE(agent_version, ''), COALESCE(kernel, ''),
		COALESCE(boot_id, ''), enrolled_at, last_heartbeat, events_dropped_total, status
		FROM agents WHERE agent_id = ?;`

	var a model.AgentRecord
	var devID sql.NullInt64
	var lastHB sql.NullTime

	err := s.r.QueryRowContext(ctx, query, agentID).Scan(
		&a.AgentID, &devID, &a.Hostname, &a.AgentVersion, &a.Kernel,
		&a.BootID, &a.EnrolledAt, &lastHB, &a.EventsDroppedTotal, &a.Status,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("querying agent %s: %w", agentID, err)
	}

	if devID.Valid {
		a.DeviceID = &devID.Int64
	}
	if lastHB.Valid {
		a.LastHeartbeat = &lastHB.Time
	}

	ifaces, err := s.getAgentInterfaces(ctx, a.AgentID)
	if err == nil {
		a.Interfaces = ifaces
	}

	return &a, nil
}

func (s *Storage) getAgentInterfaces(ctx context.Context, agentID string) ([]model.AgentInterface, error) {
	query := `SELECT name, COALESCE(mac, ''), ip FROM agent_interfaces WHERE agent_id = ? ORDER BY name ASC;`
	rows, err := s.r.QueryContext(ctx, query, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ifaceMap := make(map[string]*model.AgentInterface)
	for rows.Next() {
		var name, mac, ip string
		if err := rows.Scan(&name, &mac, &ip); err != nil {
			return nil, err
		}
		iface, ok := ifaceMap[name]
		if !ok {
			iface = &model.AgentInterface{
				Name: name,
				MAC:  mac,
			}
			ifaceMap[name] = iface
		}
		if mac != "" && iface.MAC == "" {
			iface.MAC = mac
		}
		addr, err := netip.ParseAddr(ip)
		if err == nil && addr.Is6() {
			iface.IPv6 = append(iface.IPv6, ip)
		} else {
			iface.IPv4 = append(iface.IPv4, ip)
		}
	}

	var res []model.AgentInterface
	for _, v := range ifaceMap {
		res = append(res, *v)
	}
	return res, nil
}

// GetAgentByInterfaceIP looks up an agent having an interface with the specified IP.
func (s *Storage) GetAgentByInterfaceIP(ctx context.Context, ip string) (*model.AgentRecord, error) {
	query := `SELECT agent_id FROM agent_interfaces WHERE ip = ? LIMIT 1;`
	var agentID string
	err := s.r.QueryRowContext(ctx, query, ip).Scan(&agentID)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("querying agent by ip %s: %w", ip, err)
	}
	return s.GetAgentByID(ctx, agentID)
}

// RevokeAgent sets the agent status to 'revoked'.
func (s *Storage) RevokeAgent(ctx context.Context, agentID string) error {
	query := `UPDATE agents SET status = 'revoked' WHERE agent_id = ?;`
	res, err := s.w.ExecContext(ctx, query, agentID)
	if err != nil {
		return fmt.Errorf("revoking agent %s: %w", agentID, err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// IngestBatch inserts a telemetry batch and its normalized events into the writer DB inside a single transaction.
func (s *Storage) IngestBatch(ctx context.Context, batch *model.TelemetryBatch, events []model.NormalizedEvent, rejectedCount int) (int64, bool, error) {
	now := time.Now().UTC()
	var batchID int64
	var isDuplicate bool

	err := s.WithTx(ctx, func(tx *Tx) error {
		// 1. Insert into agent_batches
		batchQuery := `INSERT INTO agent_batches (
			agent_id, boot_id, seq, received_at, event_count, rejected_count, dropped_reported, detect_pending
		) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
		ON CONFLICT(agent_id, boot_id, seq) DO NOTHING;`

		res, err := tx.tx.ExecContext(ctx, batchQuery,
			batch.Agent.AgentID, batch.Agent.BootID, batch.Batch.Seq, now,
			len(batch.Events), rejectedCount, batch.Batch.DroppedSinceLast,
		)
		if err != nil {
			return fmt.Errorf("inserting agent batch: %w", err)
		}

		rows, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("getting batch rows affected: %w", err)
		}
		if rows == 0 {
			isDuplicate = true
			return nil
		}

		batchID, err = res.LastInsertId()
		if err != nil || batchID == 0 {
			// Fallback select
			err = tx.tx.QueryRowContext(ctx,
				`SELECT id FROM agent_batches WHERE agent_id = ? AND boot_id = ? AND seq = ?;`,
				batch.Agent.AgentID, batch.Agent.BootID, batch.Batch.Seq,
			).Scan(&batchID)
			if err != nil {
				return fmt.Errorf("retrieving batch id: %w", err)
			}
		}

		// 2. Insert normalized events
		if len(events) > 0 {
			stmt, err := tx.tx.PrepareContext(ctx, `INSERT INTO agent_events (
				batch_id, agent_id, device_id, event_type, category, ts, pid, ppid, uid, gid,
				comm, image, dst_ip, dst_port, target_pid, path, command, data_json, agent_rule, agent_severity
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`)
			if err != nil {
				return fmt.Errorf("preparing event insert: %w", err)
			}
			defer stmt.Close()

			for i := range events {
				events[i].BatchID = batchID
				var dstIPStr *string
				if events[i].DstIP.IsValid() {
					s := events[i].DstIP.String()
					dstIPStr = &s
				}
				var dstPortAny any = nil
				if events[i].DstPort > 0 {
					dstPortAny = events[i].DstPort
				}
				var targetPIDAny any = nil
				if events[i].TargetPID > 0 {
					targetPIDAny = events[i].TargetPID
				}

				res, err := stmt.ExecContext(ctx,
					batchID, events[i].AgentID, events[i].DeviceID, events[i].Type, events[i].Category,
					events[i].TS.UTC(), events[i].PID, events[i].PPID, events[i].UID, events[i].GID,
					events[i].Comm, events[i].Image, dstIPStr, dstPortAny, targetPIDAny,
					events[i].Path, events[i].Command, events[i].DataJSON, events[i].AgentRule, events[i].AgentSeverity,
				)
				if err != nil {
					return fmt.Errorf("inserting event %d: %w", i, err)
				}
				eventID, _ := res.LastInsertId()
				events[i].ID = eventID
			}
		}

		// 3. Upsert agent heartbeat, boot_id, version, dropped_total
		updateAgentQuery := `UPDATE agents SET
			boot_id = ?,
			hostname = COALESCE(NULLIF(?, ''), hostname),
			agent_version = COALESCE(NULLIF(?, ''), agent_version),
			kernel = COALESCE(NULLIF(?, ''), kernel),
			last_heartbeat = ?,
			events_dropped_total = events_dropped_total + ?
		WHERE agent_id = ?;`

		_, err = tx.tx.ExecContext(ctx, updateAgentQuery,
			batch.Agent.BootID, batch.Agent.Hostname, batch.Agent.AgentVersion, batch.Agent.Kernel,
			now, batch.Batch.DroppedSinceLast, batch.Agent.AgentID,
		)
		if err != nil {
			return fmt.Errorf("updating agent heartbeat: %w", err)
		}

		// 4. Upsert interfaces (replace previous inventory with new batch)
		if len(batch.Agent.Interfaces) > 0 {
			_, _ = tx.tx.ExecContext(ctx, `DELETE FROM agent_interfaces WHERE agent_id = ?;`, batch.Agent.AgentID)

			ifaceStmt, err := tx.tx.PrepareContext(ctx,
				`INSERT INTO agent_interfaces (agent_id, name, mac, ip, updated_at) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(agent_id, name, ip) DO UPDATE SET mac = excluded.mac, updated_at = excluded.updated_at;`)
			if err != nil {
				return fmt.Errorf("preparing interface insert: %w", err)
			}
			defer ifaceStmt.Close()

			for _, iface := range batch.Agent.Interfaces {
				allIPs := append([]string(nil), iface.IPv4...)
				allIPs = append(allIPs, iface.IPv6...)
				for _, ip := range allIPs {
					if ip == "" {
						continue
					}
					if _, err := ifaceStmt.ExecContext(ctx, batch.Agent.AgentID, iface.Name, iface.MAC, ip, now); err != nil {
						return fmt.Errorf("inserting agent interface: %w", err)
					}
				}
			}
		}

		return nil
	})

	if err != nil {
		return 0, false, err
	}
	return batchID, isDuplicate, nil
}

// CountPendingBatches returns the number of batches pending detection processing.
func (s *Storage) CountPendingBatches(ctx context.Context) (int, error) {
	var count int
	err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_batches WHERE detect_pending = 1;`).Scan(&count)
	return count, err
}

// MarkBatchProcessed marks a batch as detect_pending = 0.
func (s *Storage) MarkBatchProcessed(ctx context.Context, batchID int64) error {
	_, err := s.w.ExecContext(ctx, `UPDATE agent_batches SET detect_pending = 0 WHERE id = ?;`, batchID)
	return err
}

// GetPendingBatches fetches IDs of pending batches for the dispatcher sweeper.
func (s *Storage) GetPendingBatches(ctx context.Context, limit int) ([]int64, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.r.QueryContext(ctx, `SELECT id FROM agent_batches WHERE detect_pending = 1 ORDER BY id ASC LIMIT ?;`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// GetBatchEvents retrieves normalized events for a given batch.
func (s *Storage) GetBatchEvents(ctx context.Context, batchID int64) ([]model.NormalizedEvent, error) {
	query := `SELECT id, batch_id, agent_id, device_id, '', event_type, category, '', ts,
		pid, ppid, uid, gid, comm, COALESCE(image, ''), COALESCE(dst_ip, ''), COALESCE(dst_port, 0),
		COALESCE(target_pid, 0), COALESCE(path, ''), COALESCE(command, ''), data_json,
		COALESCE(agent_rule, ''), COALESCE(agent_severity, '')
		FROM agent_events WHERE batch_id = ? ORDER BY id ASC;`

	rows, err := s.r.QueryContext(ctx, query, batchID)
	if err != nil {
		return nil, fmt.Errorf("querying batch events: %w", err)
	}
	defer rows.Close()

	var events []model.NormalizedEvent
	for rows.Next() {
		var e model.NormalizedEvent
		var devID sql.NullInt64
		var dstIPStr string
		var dummyBootID, dummyAction string

		if err := rows.Scan(
			&e.ID, &e.BatchID, &e.AgentID, &devID, &dummyBootID, &e.Type, &e.Category, &dummyAction, &e.TS,
			&e.PID, &e.PPID, &e.UID, &e.GID, &e.Comm, &e.Image, &dstIPStr, &e.DstPort,
			&e.TargetPID, &e.Path, &e.Command, &e.DataJSON, &e.AgentRule, &e.AgentSeverity,
		); err != nil {
			return nil, err
		}
		if devID.Valid {
			e.DeviceID = &devID.Int64
		}
		if dstIPStr != "" {
			if addr, err := netip.ParseAddr(dstIPStr); err == nil {
				e.DstIP = addr
			}
		}
		events = append(events, e)
	}
	return events, nil
}

// GetAgentEvents queries normalized events filtered by agent, type, time range, and limit.
func (s *Storage) GetAgentEvents(ctx context.Context, agentID, eventType string, from, to *time.Time, limit int) ([]model.NormalizedEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}

	query := `SELECT id, batch_id, agent_id, device_id, '', event_type, category, '', ts,
		pid, ppid, uid, gid, comm, COALESCE(image, ''), COALESCE(dst_ip, ''), COALESCE(dst_port, 0),
		COALESCE(target_pid, 0), COALESCE(path, ''), COALESCE(command, ''), data_json,
		COALESCE(agent_rule, ''), COALESCE(agent_severity, '')
		FROM agent_events WHERE 1=1`

	var args []any
	if agentID != "" {
		query += ` AND agent_id = ?`
		args = append(args, agentID)
	}
	if eventType != "" {
		query += ` AND event_type = ?`
		args = append(args, eventType)
	}
	if from != nil && !from.IsZero() {
		query += ` AND ts >= ?`
		args = append(args, from.UTC())
	}
	if to != nil && !to.IsZero() {
		query += ` AND ts <= ?`
		args = append(args, to.UTC())
	}

	query += ` ORDER BY ts DESC LIMIT ?;`
	args = append(args, limit)

	rows, err := s.r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying agent events: %w", err)
	}
	defer rows.Close()

	var events []model.NormalizedEvent
	for rows.Next() {
		var e model.NormalizedEvent
		var devID sql.NullInt64
		var dstIPStr string
		var dummyBootID, dummyAction string

		if err := rows.Scan(
			&e.ID, &e.BatchID, &e.AgentID, &devID, &dummyBootID, &e.Type, &e.Category, &dummyAction, &e.TS,
			&e.PID, &e.PPID, &e.UID, &e.GID, &e.Comm, &e.Image, &dstIPStr, &e.DstPort,
			&e.TargetPID, &e.Path, &e.Command, &e.DataJSON, &e.AgentRule, &e.AgentSeverity,
		); err != nil {
			return nil, err
		}
		if devID.Valid {
			e.DeviceID = &devID.Int64
		}
		if dstIPStr != "" {
			if addr, err := netip.ParseAddr(dstIPStr); err == nil {
				e.DstIP = addr
			}
		}
		events = append(events, e)
	}
	return events, nil
}
