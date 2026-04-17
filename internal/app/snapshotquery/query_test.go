package snapshotquery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSnapshot(t *testing.T, dir, name string, capturedAt time.Time) {
	t.Helper()
	doc := map[string]any{
		"schema_version": "obs.v0.1",
		"captured_at":    capturedAt.Format(time.RFC3339),
		"assets":         []any{},
	}
	data, _ := json.Marshal(doc)
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestQuery_OlderThanFilter(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)

	writeSnapshot(t, dir, "old.json", now.Add(-100*24*time.Hour))
	writeSnapshot(t, dir, "new.json", now.Add(-10*24*time.Hour))

	results, err := Query(dir, Filter{OlderThan: 90 * 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1 (only old)", len(results))
	}
}

func TestQuery_MalformedDetected(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	// Write a malformed file (missing captured_at).
	doc := map[string]any{"schema_version": "obs.v0.1"}
	data, _ := json.Marshal(doc)
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	health, err := Health(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(health.Malformed) != 1 {
		t.Fatalf("malformed = %d, want 1", len(health.Malformed))
	}
	if health.Malformed[0].ErrorReason != "missing captured_at" {
		t.Errorf("reason = %s, want missing captured_at", health.Malformed[0].ErrorReason)
	}
}
