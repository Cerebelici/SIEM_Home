package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gr0gu/cerberus/internal/model"
)

const settingsKeyGeneral = "general_settings"

// GetAppSettings retrieves persisted settings from SQLite, falling back to defaults for any unset values.
func (s *Storage) GetAppSettings(ctx context.Context, defaults model.AppSettings) (model.AppSettings, error) {
	var val string
	err := s.r.QueryRowContext(ctx, "SELECT value FROM app_settings WHERE key = ?;", settingsKeyGeneral).Scan(&val)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return defaults, nil
		}
		return defaults, fmt.Errorf("querying app_settings: %w", err)
	}

	var res model.AppSettings
	if err := json.Unmarshal([]byte(val), &res); err != nil {
		return defaults, fmt.Errorf("decoding app_settings: %w", err)
	}

	// Fill any zero fields with provided defaults
	if res.NetworkMode == "" {
		res.NetworkMode = defaults.NetworkMode
	}
	if res.DiscoveryIntervalSec <= 0 {
		res.DiscoveryIntervalSec = defaults.DiscoveryIntervalSec
	}
	if res.VulnIntervalSec <= 0 {
		res.VulnIntervalSec = defaults.VulnIntervalSec
	}
	if res.NmapPath == "" {
		res.NmapPath = defaults.NmapPath
	}

	return res, nil
}

// SaveAppSettings writes or replaces application settings in SQLite.
func (s *Storage) SaveAppSettings(ctx context.Context, settings model.AppSettings) error {
	raw, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("encoding app_settings: %w", err)
	}

	query := `
		INSERT INTO app_settings (key, value, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET
			value = excluded.value,
			updated_at = CURRENT_TIMESTAMP;
	`
	_, err = s.w.ExecContext(ctx, query, settingsKeyGeneral, string(raw))
	if err != nil {
		return fmt.Errorf("persisting app_settings: %w", err)
	}
	return nil
}

