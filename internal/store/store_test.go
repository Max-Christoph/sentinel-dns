package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "nested", "sentinel.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return st
}

func TestOpenUsesWAL(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	var mode string
	if err := st.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}
	var version int
	if err := st.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("user_version: %v", err)
	}
	if version != schemaVersion {
		t.Fatalf("user_version = %d, want %d", version, schemaVersion)
	}
}

func TestRecordDecisionUpsertsAndCountsHits(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	ctx := context.Background()
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	first := Decision{
		Domain:         "metrics.vendor.example",
		DeviceCategory: "telemetry",
		IsTelemetry:    true,
		Blocked:        true,
		Confidence:     0.93,
		Reasoning:      "metrics label",
		ClientIP:       "192.168.88.50",
		CreatedAt:      created,
	}
	if err := st.RecordDecision(ctx, first); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}

	second := first
	second.Confidence = 0.97
	second.CreatedAt = created.Add(time.Hour)
	if err := st.RecordDecision(ctx, second); err != nil {
		t.Fatalf("RecordDecision (update): %v", err)
	}

	got, err := st.Get(ctx, first.Domain)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HitCount != 2 {
		t.Errorf("hit_count = %d, want 2", got.HitCount)
	}
	if got.Confidence != 0.97 {
		t.Errorf("confidence = %v, want 0.97", got.Confidence)
	}
	if !got.Blocked || !got.IsTelemetry {
		t.Errorf("flags lost: %+v", got)
	}
	if !got.CreatedAt.Equal(created) {
		t.Errorf("created_at = %v, want %v", got.CreatedAt, created)
	}
	if !got.UpdatedAt.After(created) {
		t.Errorf("updated_at = %v, want later than created_at", got.UpdatedAt)
	}
}

func TestGetUnknownReturnsErrNoRows(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	_, err := st.Get(context.Background(), "missing.example")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("want sql.ErrNoRows, got %v", err)
	}
}

func TestAllAndStats(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	ctx := context.Background()
	for _, d := range []Decision{
		{Domain: "a.example", Blocked: true, Confidence: 0.9, IsTelemetry: true},
		{Domain: "b.example", Blocked: false, Confidence: 0.2},
	} {
		if err := st.RecordDecision(ctx, d); err != nil {
			t.Fatalf("RecordDecision %s: %v", d.Domain, err)
		}
	}
	all, err := st.All(ctx)
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("len(All) = %d, want 2", len(all))
	}
	stats, err := st.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Domains != 2 || stats.Blocked != 1 || stats.Hits != 2 {
		t.Fatalf("stats = %+v, want 2 domains, 1 blocked, 2 hits", stats)
	}
}

func TestUpdateCategoryKeepsDecision(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	ctx := context.Background()
	if err := st.RecordDecision(ctx, Decision{
		Domain: "ads.example", Blocked: true, Confidence: 0.91, IsTelemetry: true, Reasoning: "noul p=0.910",
	}); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}

	updated, err := st.UpdateCategory(ctx, "ads.example", "analytics")
	if err != nil {
		t.Fatalf("UpdateCategory: %v", err)
	}
	if !updated {
		t.Fatal("UpdateCategory reported no row")
	}
	got, err := st.Get(ctx, "ads.example")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DeviceCategory != "analytics" {
		t.Errorf("device_category = %q, want analytics", got.DeviceCategory)
	}
	if !got.Blocked || got.Confidence != 0.91 || got.Reasoning != "noul p=0.910" {
		t.Errorf("decision was modified by the category backfill: %+v", got)
	}
	if got.HitCount != 1 {
		t.Errorf("hit_count = %d, want 1 (enrichment is not a classification)", got.HitCount)
	}

	if updated, err := st.UpdateCategory(ctx, "missing.example", "ads"); err != nil || updated {
		t.Fatalf("unknown domain: updated=%v err=%v, want false and no error", updated, err)
	}
}

func TestPruneBefore(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	ctx := context.Background()
	if err := st.RecordDecision(ctx, Decision{Domain: "old.example", Confidence: 0.5}); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}
	// Force updated_at into the past.
	if _, err := st.db.Exec("UPDATE decisions SET updated_at = ? WHERE domain = ?",
		formatTime(time.Now().Add(-48*time.Hour)), "old.example"); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	removed, err := st.PruneBefore(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("PruneBefore: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
}

func TestRecordRejectsEmptyDomain(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	if err := st.RecordDecision(context.Background(), Decision{}); err == nil {
		t.Fatal("want error for empty domain")
	}
}
