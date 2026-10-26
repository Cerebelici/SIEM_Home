package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// GetOrCreateClientID returns the persisted client UUID from app_metadata,
// or creates and persists a new one if it does not yet exist.
func (s *Storage) GetOrCreateClientID(ctx context.Context) (string, error) {
	if s == nil || s.w == nil {
		return uuid.NewString(), nil
	}

	// Ensure app_metadata exists
	_, err := s.w.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS app_metadata (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
	`)
	if err != nil {
		return uuid.NewString(), fmt.Errorf("creating app_metadata table: %w", err)
	}

	var clientID string
	err = s.r.QueryRowContext(ctx, `SELECT value FROM app_metadata WHERE key = 'client_id'`).Scan(&clientID)
	if err == nil && clientID != "" {
		return clientID, nil
	}

	newID := uuid.NewString()
	_, err = s.w.ExecContext(ctx, `
		INSERT OR IGNORE INTO app_metadata (key, value) VALUES ('client_id', ?);
	`, newID)
	if err != nil {
		return newID, fmt.Errorf("inserting client_id into app_metadata: %w", err)
	}

	// Read back the authoritative value in case of concurrent insert
	err = s.r.QueryRowContext(ctx, `SELECT value FROM app_metadata WHERE key = 'client_id'`).Scan(&clientID)
	if err == nil && clientID != "" {
		return clientID, nil
	}

	return newID, nil
}
