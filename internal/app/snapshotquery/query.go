// Package snapshotquery provides filtered access to snapshot archives
// for retention analysis, health checks, and pipeline composition.
// Stave reads only — never deletes or modifies files.
package snapshotquery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SnapshotInfo holds metadata about one snapshot file.
type SnapshotInfo struct {
	Path          string    `json:"path"`
	CapturedAt    time.Time `json:"captured_at"`
	AgeDays       float64   `json:"age_days"`
	SizeBytes     int64     `json:"size_bytes"`
	SchemaVersion string    `json:"schema_version"`
	AssetCount    int       `json:"asset_count"`
	SchemaValid   bool      `json:"schema_valid"`
	ErrorReason   string    `json:"error_reason,omitempty"`
}

// HealthReport summarizes archive health.
type HealthReport struct {
	Total       int            `json:"total"`
	SchemaValid int            `json:"schema_valid"`
	Malformed   []SnapshotInfo `json:"malformed,omitempty"`
	ByAge       AgeBreakdown   `json:"by_age"`
}

// AgeBreakdown groups snapshots by age.
type AgeBreakdown struct {
	Under30    int `json:"under_30d"`
	From30To90 int `json:"30_to_90d"`
	Over90     int `json:"over_90d"`
}

// Filter constrains the query.
type Filter struct {
	OlderThan  time.Duration
	NewerThan  time.Duration
	RangeStart time.Time
	RangeEnd   time.Time
	Now        time.Time
}

// Query scans a directory and returns matching snapshot metadata.
func Query(dir string, f Filter) ([]SnapshotInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory: %w", err)
	}

	var results []SnapshotInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info := parseSnapshotInfo(path, f.Now)

		if !matchesFilter(info, f) {
			continue
		}
		results = append(results, info)
	}
	return results, nil
}

// Health produces a health report for the archive.
func Health(dir string, now time.Time) (*HealthReport, error) {
	all, err := Query(dir, Filter{Now: now})
	if err != nil {
		return nil, err
	}

	report := &HealthReport{Total: len(all)}
	for i := range all {
		s := &all[i]
		if s.SchemaValid {
			report.SchemaValid++
		} else {
			report.Malformed = append(report.Malformed, *s)
		}
		switch {
		case s.AgeDays < 30:
			report.ByAge.Under30++
		case s.AgeDays < 90:
			report.ByAge.From30To90++
		default:
			report.ByAge.Over90++
		}
	}
	return report, nil
}

func parseSnapshotInfo(path string, now time.Time) SnapshotInfo {
	info := SnapshotInfo{
		Path:        path,
		SchemaValid: true,
	}

	stat, err := os.Stat(path)
	if err == nil {
		info.SizeBytes = stat.Size()
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304: path is enumerated by the caller from a snapshot directory it already validated
	if err != nil {
		info.SchemaValid = false
		info.ErrorReason = "unreadable"
		return info
	}

	var doc struct {
		SchemaVersion string `json:"schema_version"`
		CapturedAt    string `json:"captured_at"`
		Snapshots     []struct {
			CapturedAt string `json:"captured_at"`
			Assets     []any  `json:"assets"`
		} `json:"snapshots"`
		Assets []any `json:"assets"`
	}
	if jsonErr := json.Unmarshal(data, &doc); jsonErr != nil {
		info.SchemaValid = false
		info.ErrorReason = "invalid JSON"
		return info
	}

	info.SchemaVersion = doc.SchemaVersion

	// Try bundle format.
	if len(doc.Snapshots) > 0 {
		last := doc.Snapshots[len(doc.Snapshots)-1]
		if t, err := time.Parse(time.RFC3339, last.CapturedAt); err == nil {
			info.CapturedAt = t
		}
		info.AssetCount = len(last.Assets)
	} else {
		// Single snapshot format.
		if t, err := time.Parse(time.RFC3339, doc.CapturedAt); err == nil {
			info.CapturedAt = t
		}
		info.AssetCount = len(doc.Assets)
	}

	if info.CapturedAt.IsZero() {
		info.SchemaValid = false
		info.ErrorReason = "missing captured_at"
	}

	if !info.CapturedAt.IsZero() && !now.IsZero() {
		info.AgeDays = now.Sub(info.CapturedAt).Hours() / 24
	}

	return info
}

func matchesFilter(info SnapshotInfo, f Filter) bool {
	if f.OlderThan > 0 {
		cutoff := f.Now.Add(-f.OlderThan)
		if info.CapturedAt.After(cutoff) || info.CapturedAt.IsZero() {
			return false
		}
	}
	if f.NewerThan > 0 {
		cutoff := f.Now.Add(-f.NewerThan)
		if info.CapturedAt.Before(cutoff) {
			return false
		}
	}
	if !f.RangeStart.IsZero() && info.CapturedAt.Before(f.RangeStart) {
		return false
	}
	if !f.RangeEnd.IsZero() && info.CapturedAt.After(f.RangeEnd) {
		return false
	}
	return true
}
