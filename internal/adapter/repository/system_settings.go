package repository

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SystemSettingsRepo stores arbitrary JSON-valued settings keyed by a string.
// Used for admin-configurable values like data retention windows.
type SystemSettingsRepo struct {
	db *pgxpool.Pool
}

func NewSystemSettingsRepo(db *pgxpool.Pool) *SystemSettingsRepo {
	return &SystemSettingsRepo{db: db}
}

// GetJSON reads a key from system_settings and unmarshals into dst.
// Returns nil if the key doesn't exist.
func (r *SystemSettingsRepo) GetJSON(ctx context.Context, key string, dst any) error {
	var raw []byte
	err := r.db.QueryRow(ctx,
		`SELECT value FROM system_settings WHERE key = $1`, key,
	).Scan(&raw)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	}
	return json.Unmarshal(raw, dst)
}

// SetJSON upserts a key in system_settings.
func (r *SystemSettingsRepo) SetJSON(ctx context.Context, key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(ctx,
		`INSERT INTO system_settings (key, value, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
		key, raw,
	)
	return err
}
