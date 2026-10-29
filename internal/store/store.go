// Package store persists classification decisions in a pure-Go SQLite
// database (modernc.org/sqlite, no CGO).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers driver "sqlite"
)

// Decision is one classified domain together with its observed hit count.
type Decision struct {
	Domain         string    `json:"domain"`
	DeviceCategory string    `json:"device_category"`
	IsTelemetry    bool      `json:"is_telemetry"`
	Blocked        bool      `json:"blocked"`
	Confidence     float64   `json:"confidence"`
	Reasoning      string    `json:"reasoning"`
	ClientIP       string    `json:"client_ip"`
	HitCount       int64     `json:"hit_count"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Stats summarizes the decision table.
type Stats struct {
	Domains int64 `json:"domains"`
	Blocked int64 `json:"blocked"`
	Hits    int64 `json:"hits"`
}

// Store wraps the SQLite connection. It is safe for concurrent use.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

const schemaVersion = 1

const migrationsSQL = `
CREATE TABLE IF NOT EXISTS decisions (
	domain          TEXT    PRIMARY KEY,
	device_category TEXT    NOT NULL DEFAULT '',
	is_telemetry    INTEGER NOT NULL DEFAULT 0 CHECK (is_telemetry IN (0,1)),
	blocked         INTEGER NOT NULL DEFAULT 0 CHECK (blocked IN (0,1)),
	confidence      REAL    NOT NULL DEFAULT 0 CHECK (confidence >= 0 AND confidence <= 1),
	reasoning       TEXT    NOT NULL DEFAULT '',
	client_ip       TEXT    NOT NULL DEFAULT '',
	hit_count       INTEGER NOT NULL DEFAULT 1 CHECK (hit_count >= 0),
	created_at      TEXT    NOT NULL,
	updated_at      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_blocked ON decisions(blocked);
CREATE INDEX IF NOT EXISTS idx_decisions_updated_at ON decisions(updated_at);
`

// Open creates the parent directory, opens the database in WAL mode and runs
// the migrations. A single connection is kept because SQLite allows exactly
// one writer; all reads are served from the in-memory cache anyway.
func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("store: empty database path")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("store: create data directory: %w", err)
		}
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	s := &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
	if err := s.initialize(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) initialize(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, migrationsSQL); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	var mode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return fmt.Errorf("store: read journal_mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("store: expected WAL journal mode, got %q", mode)
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	if version < schemaVersion {
		if _, err := s.db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
			return fmt.Errorf("store: set schema version: %w", err)
		}
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA wal_autocheckpoint = 1000"); err != nil {
		return fmt.Errorf("store: configure wal_autocheckpoint: %w", err)
	}
	return nil
}

// Close flushes the WAL and closes the connection.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	_, _ = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	return nil
}

// RecordDecision upserts a decision and increments hit_count on conflict.
// created_at is preserved for existing domains.
func (s *Store) RecordDecision(ctx context.Context, d Decision) error {
	if strings.TrimSpace(d.Domain) == "" {
		return errors.New("store: domain must not be empty")
	}
	now := s.now()
	if d.CreatedAt.IsZero() {
		d.CreatedAt = now
	}
	d.UpdatedAt = now
	const q = `
INSERT INTO decisions (domain, device_category, is_telemetry, blocked, confidence, reasoning, client_ip, hit_count, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
ON CONFLICT(domain) DO UPDATE SET
	device_category = excluded.device_category,
	is_telemetry    = excluded.is_telemetry,
	blocked         = excluded.blocked,
	confidence      = excluded.confidence,
	reasoning       = excluded.reasoning,
	client_ip       = excluded.client_ip,
	hit_count       = decisions.hit_count + 1,
	updated_at      = excluded.updated_at`
	_, err := s.db.ExecContext(ctx, q,
		d.Domain, d.DeviceCategory, boolToInt(d.IsTelemetry), boolToInt(d.Blocked),
		clamp(d.Confidence), d.Reasoning, d.ClientIP,
		formatTime(d.CreatedAt), formatTime(d.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("store: record %s: %w", d.Domain, err)
	}
	return nil
}

// UpdateCategory backfills device_category for an existing decision. It does
// not touch blocked, confidence, reasoning or hit_count, so the audit trail of
// the original decision stays intact. Returns false when the domain is unknown.
func (s *Store) UpdateCategory(ctx context.Context, domain, category string) (bool, error) {
	if strings.TrimSpace(domain) == "" {
		return false, errors.New("store: domain must not be empty")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE decisions SET device_category = ?, updated_at = ? WHERE domain = ?`,
		category, formatTime(s.now()), domain)
	if err != nil {
		return false, fmt.Errorf("store: update category %s: %w", domain, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: update category rows affected: %w", err)
	}
	return affected > 0, nil
}

// All returns every stored decision, ordered by most recently updated. It is
// used once at startup to warm the in-memory cache.
func (s *Store) All(ctx context.Context) ([]Decision, error) {
	const q = `SELECT domain, device_category, is_telemetry, blocked, confidence, reasoning, client_ip, hit_count, created_at, updated_at
FROM decisions ORDER BY updated_at DESC`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("store: list decisions: %w", err)
	}
	defer rows.Close()

	var out []Decision
	for rows.Next() {
		var (
			d                Decision
			isTelemetry, blk int
			created, updated string
		)
		if err := rows.Scan(&d.Domain, &d.DeviceCategory, &isTelemetry, &blk, &d.Confidence,
			&d.Reasoning, &d.ClientIP, &d.HitCount, &created, &updated); err != nil {
			return nil, fmt.Errorf("store: scan decision: %w", err)
		}
		d.IsTelemetry = isTelemetry == 1
		d.Blocked = blk == 1
		d.CreatedAt = parseTime(created)
		d.UpdatedAt = parseTime(updated)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate decisions: %w", err)
	}
	return out, nil
}

// Get returns a single decision. sql.ErrNoRows is returned when unknown.
func (s *Store) Get(ctx context.Context, domain string) (Decision, error) {
	const q = `SELECT domain, device_category, is_telemetry, blocked, confidence, reasoning, client_ip, hit_count, created_at, updated_at
FROM decisions WHERE domain = ?`
	var (
		d                Decision
		isTelemetry, blk int
		created, updated string
	)
	err := s.db.QueryRowContext(ctx, q, domain).Scan(&d.Domain, &d.DeviceCategory, &isTelemetry, &blk,
		&d.Confidence, &d.Reasoning, &d.ClientIP, &d.HitCount, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return Decision{}, sql.ErrNoRows
	}
	if err != nil {
		return Decision{}, fmt.Errorf("store: get %s: %w", domain, err)
	}
	d.IsTelemetry = isTelemetry == 1
	d.Blocked = blk == 1
	d.CreatedAt = parseTime(created)
	d.UpdatedAt = parseTime(updated)
	return d, nil
}

// Stats aggregates the decision table for diagnostics.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(blocked),0), COALESCE(SUM(hit_count),0) FROM decisions`).
		Scan(&st.Domains, &st.Blocked, &st.Hits)
	if err != nil {
		return Stats{}, fmt.Errorf("store: stats: %w", err)
	}
	return st, nil
}

// PruneBefore deletes decisions older than cutoff. Returns the number removed.
func (s *Store) PruneBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM decisions WHERE updated_at < ?`, formatTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: prune: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: prune rows affected: %w", err)
	}
	return n, nil
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTime(raw string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func clamp(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}
