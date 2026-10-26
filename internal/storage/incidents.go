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

// IncidentStore defines storage operations required by the threat detection engine.
type IncidentStore interface {
	UpsertIncident(ctx context.Context, inc *model.Incident, dedupeWindow time.Duration) (*model.Incident, bool, error)
	GetDeviceIDForAgent(ctx context.Context, agentID string) (*int64, error)
	CountOpenIncidents(ctx context.Context) (int, error)
}

// UpsertIncident inserts a new incident or deduplicates against an existing open incident within the dedupe window.
func (s *Storage) UpsertIncident(ctx context.Context, inc *model.Incident, dedupeWindow time.Duration) (*model.Incident, bool, error) {
	if inc == nil {
		return nil, false, fmt.Errorf("incident cannot be nil")
	}

	// 1. Resolve DeviceID if not already bound
	if inc.DeviceID == nil && inc.AgentID != "" {
		devID, err := s.GetDeviceIDForAgent(ctx, inc.AgentID)
		if err == nil && devID != nil {
			inc.DeviceID = devID
		}
	}

	if inc.FirstSeenAt.IsZero() {
		inc.FirstSeenAt = time.Now().UTC()
	}
	if inc.LastSeenAt.IsZero() {
		inc.LastSeenAt = inc.FirstSeenAt
	}
	if inc.HitCount <= 0 {
		inc.HitCount = 1
	}
	if inc.Status == "" {
		inc.Status = "open"
	}

	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin incident tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 2. Check for an existing incident matching dedupe_key within dedupeWindow
	cutoff := inc.LastSeenAt.Add(-dedupeWindow)
	var (
		existingID          int64
		existingFirstSeen   time.Time
		existingHitCount    int
		existingEvidenceRaw string
	)

	query := `SELECT id, first_seen_at, hit_count, evidence_event_ids FROM incidents 
              WHERE dedupe_key = ? AND status = 'open' AND last_seen_at >= ? 
              ORDER BY last_seen_at DESC LIMIT 1`
	err = tx.QueryRowContext(ctx, query, inc.DedupeKey, cutoff).Scan(
		&existingID, &existingFirstSeen, &existingHitCount, &existingEvidenceRaw,
	)

	if err == nil {
		// Existing incident found -> update hit_count, last_seen_at, merge evidence
		var existingIDs []int64
		_ = json.Unmarshal([]byte(existingEvidenceRaw), &existingIDs)

		seenMap := make(map[int64]bool)
		for _, id := range existingIDs {
			seenMap[id] = true
		}
		mergedIDs := append([]int64(nil), existingIDs...)
		for _, id := range inc.EvidenceEventIDs {
			if !seenMap[id] && len(mergedIDs) < 50 {
				seenMap[id] = true
				mergedIDs = append(mergedIDs, id)
			}
		}

		newEvidenceBytes, _ := json.Marshal(mergedIDs)
		newHitCount := existingHitCount + 1

		updateQuery := `UPDATE incidents SET last_seen_at = ?, hit_count = ?, evidence_event_ids = ? WHERE id = ?`
		if _, err := tx.ExecContext(ctx, updateQuery, inc.LastSeenAt, newHitCount, string(newEvidenceBytes), existingID); err != nil {
			return nil, false, fmt.Errorf("updating deduplicated incident %d: %w", existingID, err)
		}

		if err := tx.Commit(); err != nil {
			return nil, false, fmt.Errorf("commit incident update: %w", err)
		}

		inc.ID = existingID
		inc.FirstSeenAt = existingFirstSeen
		inc.HitCount = newHitCount
		inc.EvidenceEventIDs = mergedIDs
		return inc, false, nil
	} else if err != sql.ErrNoRows {
		return nil, false, fmt.Errorf("checking dedupe key: %w", err)
	}

	// 3. New incident -> insert row
	evBytes, _ := json.Marshal(inc.EvidenceEventIDs)
	if len(inc.EvidenceEventIDs) == 0 {
		evBytes = []byte("[]")
	}

	insertQuery := `INSERT INTO incidents (
		device_id, agent_id, rule_id, ruleset_version, title, severity, score,
		mitre_tactic, mitre_technique, pid_root, dedupe_key,
		first_seen_at, last_seen_at, hit_count, evidence_event_ids, status
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	res, err := tx.ExecContext(ctx, insertQuery,
		inc.DeviceID, inc.AgentID, inc.RuleID, inc.RulesetVersion, inc.Title, inc.Severity, inc.Score,
		inc.MitreTactic, inc.MitreTechnique, inc.PIDRoot, inc.DedupeKey,
		inc.FirstSeenAt, inc.LastSeenAt, inc.HitCount, string(evBytes), inc.Status,
	)
	if err != nil {
		return nil, false, fmt.Errorf("inserting incident: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, false, fmt.Errorf("getting incident last insert id: %w", err)
	}
	inc.ID = id

	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit incident insert: %w", err)
	}

	return inc, true, nil
}

// GetDeviceIDForAgent retrieves the bound device ID for an agent, if any.
func (s *Storage) GetDeviceIDForAgent(ctx context.Context, agentID string) (*int64, error) {
	var devID sql.NullInt64
	err := s.r.QueryRowContext(ctx, `SELECT device_id FROM agents WHERE agent_id = ?`, agentID).Scan(&devID)
	if err != nil {
		return nil, err
	}
	if devID.Valid {
		val := devID.Int64
		return &val, nil
	}
	return nil, nil
}

// GetIncidents retrieves incidents matching the provided filter criteria.
func (s *Storage) GetIncidents(ctx context.Context, filter model.IncidentFilter) ([]model.Incident, error) {
	var (
		conditions []string
		args       []interface{}
	)

	if filter.Status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, filter.Status)
	}
	if filter.Severity != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, strings.ToUpper(filter.Severity))
	}
	if filter.DeviceID != nil {
		conditions = append(conditions, "device_id = ?")
		args = append(args, *filter.DeviceID)
	}
	if filter.From != nil {
		conditions = append(conditions, "last_seen_at >= ?")
		args = append(args, *filter.From)
	}
	if filter.To != nil {
		conditions = append(conditions, "last_seen_at <= ?")
		args = append(args, *filter.To)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}

	query := fmt.Sprintf(`SELECT id, device_id, agent_id, rule_id, ruleset_version, title, severity, score,
		mitre_tactic, mitre_technique, pid_root, dedupe_key,
		first_seen_at, last_seen_at, hit_count, evidence_event_ids, status
		FROM incidents %s ORDER BY last_seen_at DESC LIMIT ? OFFSET ?`, whereClause)
	args = append(args, limit, filter.Offset)

	rows, err := s.r.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying incidents: %w", err)
	}
	defer rows.Close()

	var incidents []model.Incident
	for rows.Next() {
		var (
			inc       model.Incident
			devID     sql.NullInt64
			pidRoot   sql.NullInt64
			evRaw     string
			tactic    sql.NullString
			technique sql.NullString
		)

		err := rows.Scan(
			&inc.ID, &devID, &inc.AgentID, &inc.RuleID, &inc.RulesetVersion, &inc.Title, &inc.Severity, &inc.Score,
			&tactic, &technique, &pidRoot, &inc.DedupeKey,
			&inc.FirstSeenAt, &inc.LastSeenAt, &inc.HitCount, &evRaw, &inc.Status,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning incident row: %w", err)
		}

		if devID.Valid {
			v := devID.Int64
			inc.DeviceID = &v
		}
		if pidRoot.Valid {
			inc.PIDRoot = uint32(pidRoot.Int64)
		}
		if tactic.Valid {
			inc.MitreTactic = tactic.String
		}
		if technique.Valid {
			inc.MitreTechnique = technique.String
		}

		_ = json.Unmarshal([]byte(evRaw), &inc.EvidenceEventIDs)
		incidents = append(incidents, inc)
	}

	if incidents == nil {
		incidents = []model.Incident{}
	}

	return incidents, rows.Err()
}

// GetIncidentByID fetches a specific incident by its primary key, joining evidence events.
func (s *Storage) GetIncidentByID(ctx context.Context, id int64) (*model.Incident, error) {
	query := `SELECT id, device_id, agent_id, rule_id, ruleset_version, title, severity, score,
		mitre_tactic, mitre_technique, pid_root, dedupe_key,
		first_seen_at, last_seen_at, hit_count, evidence_event_ids, status
		FROM incidents WHERE id = ?`

	var (
		inc       model.Incident
		devID     sql.NullInt64
		pidRoot   sql.NullInt64
		evRaw     string
		tactic    sql.NullString
		technique sql.NullString
	)

	err := s.r.QueryRowContext(ctx, query, id).Scan(
		&inc.ID, &devID, &inc.AgentID, &inc.RuleID, &inc.RulesetVersion, &inc.Title, &inc.Severity, &inc.Score,
		&tactic, &technique, &pidRoot, &inc.DedupeKey,
		&inc.FirstSeenAt, &inc.LastSeenAt, &inc.HitCount, &evRaw, &inc.Status,
	)
	if err != nil {
		return nil, err
	}

	if devID.Valid {
		v := devID.Int64
		inc.DeviceID = &v
	}
	if pidRoot.Valid {
		inc.PIDRoot = uint32(pidRoot.Int64)
	}
	if tactic.Valid {
		inc.MitreTactic = tactic.String
	}
	if technique.Valid {
		inc.MitreTechnique = technique.String
	}

	_ = json.Unmarshal([]byte(evRaw), &inc.EvidenceEventIDs)

	// Join evidence events if IDs present
	if len(inc.EvidenceEventIDs) > 0 {
		placeholders := make([]string, len(inc.EvidenceEventIDs))
		args := make([]any, len(inc.EvidenceEventIDs))
		for i, eid := range inc.EvidenceEventIDs {
			placeholders[i] = "?"
			args[i] = eid
		}

		evQuery := fmt.Sprintf(`SELECT id, batch_id, agent_id, device_id, event_type, category, ts,
			pid, ppid, uid, gid, comm, image, dst_ip, dst_port, target_pid, path, command, data_json,
			agent_rule, agent_severity
			FROM agent_events WHERE id IN (%s) ORDER BY ts ASC`, strings.Join(placeholders, ","))

		evRows, err := s.r.QueryContext(ctx, evQuery, args...)
		if err == nil {
			defer evRows.Close()
			for evRows.Next() {
				var (
					ev        model.NormalizedEvent
					eDevID    sql.NullInt64
					pid       sql.NullInt64
					ppid      sql.NullInt64
					uid       sql.NullInt64
					gid       sql.NullInt64
					comm      sql.NullString
					image     sql.NullString
					dstIP     sql.NullString
					dstPort   sql.NullInt64
					targetPID sql.NullInt64
					path      sql.NullString
					command   sql.NullString
					dataJSON  sql.NullString
					agentRule sql.NullString
					agentSev  sql.NullString
				)

				if err := evRows.Scan(
					&ev.ID, &ev.BatchID, &ev.AgentID, &eDevID, &ev.Type, &ev.Category, &ev.TS,
					&pid, &ppid, &uid, &gid, &comm, &image, &dstIP, &dstPort, &targetPID,
					&path, &command, &dataJSON, &agentRule, &agentSev,
				); err == nil {
					if eDevID.Valid {
						v := eDevID.Int64
						ev.DeviceID = &v
					}
					if pid.Valid {
						ev.PID = uint32(pid.Int64)
					}
					if ppid.Valid {
						ev.PPID = uint32(ppid.Int64)
					}
					if uid.Valid {
						ev.UID = uint32(uid.Int64)
					}
					if gid.Valid {
						ev.GID = uint32(gid.Int64)
					}
					if comm.Valid {
						ev.Comm = comm.String
					}
					if image.Valid {
						ev.Image = image.String
					}
					if dstPort.Valid {
						ev.DstPort = uint16(dstPort.Int64)
					}
					if targetPID.Valid {
						ev.TargetPID = uint32(targetPID.Int64)
					}
					if path.Valid {
						ev.Path = path.String
					}
					if command.Valid {
						ev.Command = command.String
					}
					if dataJSON.Valid {
						ev.DataJSON = dataJSON.String
					}
					if agentRule.Valid {
						ev.AgentRule = agentRule.String
					}
					if agentSev.Valid {
						ev.AgentSeverity = agentSev.String
					}
					inc.EvidenceEvents = append(inc.EvidenceEvents, ev)
				}
			}
		}
	}

	if inc.EvidenceEvents == nil {
		inc.EvidenceEvents = []model.NormalizedEvent{}
	}

	return &inc, nil
}

// UpdateIncidentStatus updates the status of an incident (open, acknowledged, closed).
func (s *Storage) UpdateIncidentStatus(ctx context.Context, id int64, status string) error {
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "open" && status != "acknowledged" && status != "closed" {
		return fmt.Errorf("invalid incident status: %s (must be open, acknowledged, or closed)", status)
	}

	res, err := s.w.ExecContext(ctx, `UPDATE incidents SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return fmt.Errorf("updating incident status: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CountOpenIncidents returns the number of incidents currently in 'open' status.
func (s *Storage) CountOpenIncidents(ctx context.Context) (int, error) {
	var count int
	err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM incidents WHERE status = 'open'`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting open incidents: %w", err)
	}
	return count, nil
}
