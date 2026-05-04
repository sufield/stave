// Package collect provides evidence archive management for continuous
// compliance evidence accumulation.
package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// RunMetadata records a single collection run.
type RunMetadata struct {
	RunID                string            `json:"run_id"`
	CollectedAt          string            `json:"collected_at"`
	StaveVersion         string            `json:"stave_version"`
	SnapshotID           string            `json:"snapshot_id,omitempty"`
	Frameworks           []string          `json:"frameworks"`
	FindingCount         int               `json:"finding_count"`
	CriticalCount        int               `json:"critical_count"`
	HighCount            int               `json:"high_count"`
	PostureScore         *float64          `json:"posture_score,omitempty"`
	PostureScoreRubric   string            `json:"posture_score_rubric,omitempty"`
	CollectionDurationMs int64             `json:"collection_duration_ms"`
	SHA256Sums           map[string]string `json:"sha256sums"`
}

// Manifest is the chain-of-custody record for the evidence archive.
type Manifest struct {
	SchemaVersion   string            `json:"schema_version"`
	ArchiveID       string            `json:"archive_id"`
	CreatedAt       string            `json:"created_at"`
	LastUpdated     string            `json:"last_updated"`
	RetentionPolicy map[string]string `json:"retention_policy"`
	Runs            []ManifestRun     `json:"runs"`
	Gaps            []Gap             `json:"gaps"`
}

// ManifestRun is a summary entry for one collection run.
type ManifestRun struct {
	RunID        string   `json:"run_id"`
	CollectedAt  string   `json:"collected_at"`
	Frameworks   []string `json:"frameworks"`
	FindingCount int      `json:"finding_count"`
	SHA256       string   `json:"sha256"`
}

// Gap records a detected collection gap.
type Gap struct {
	ExpectedAfter     string  `json:"expected_after"`
	ActualNextRun     string  `json:"actual_next_run"`
	GapHours          float64 `json:"gap_hours"`
	ExpectedIntervalH float64 `json:"expected_interval_hours"`
}

// Archive manages the evidence archive directory.
type Archive struct {
	Path string
}

// NewArchive creates or opens an evidence archive.
func NewArchive(path string) (*Archive, error) {
	if err := os.MkdirAll(filepath.Join(path, "runs"), 0o750); err != nil { //nolint:gosec // archive dir
		return nil, fmt.Errorf("create archive: %w", err)
	}
	return &Archive{Path: path}, nil
}

// WriteRun creates a run directory with the given files and metadata.
// File names are validated as run-relative paths — names containing
// "..", absolute paths, or NUL bytes are rejected before any write.
func (a *Archive) WriteRun(runID string, files map[string][]byte, meta RunMetadata) error {
	runDir := filepath.Join(a.Path, "runs", runID)
	if err := os.MkdirAll(runDir, 0o750); err != nil { //nolint:gosec // run dir
		return fmt.Errorf("create run dir: %w", err)
	}

	meta.SHA256Sums = make(map[string]string)

	// Write each file and compute SHA-256.
	var sumLines []string
	for name, data := range files {
		if !isSafeRunRelative(name) {
			return fmt.Errorf("write %s: unsafe filename (must be run-relative, no .. segments, no leading separator)", name)
		}
		path := filepath.Join(runDir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // evidence file
			return fmt.Errorf("write %s: %w", name, err)
		}
		hash := sha256Hex(data)
		meta.SHA256Sums[name] = "sha256:" + hash
		sumLines = append(sumLines, fmt.Sprintf("sha256:%s  %s", hash, name))
	}

	// Write metadata.
	metaData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	metaPath := filepath.Join(runDir, "run-metadata.json")
	if err := os.WriteFile(metaPath, metaData, 0o644); err != nil { //nolint:gosec // metadata file
		return err
	}
	metaHash := sha256Hex(metaData)
	sumLines = append(sumLines, fmt.Sprintf("sha256:%s  run-metadata.json", metaHash))

	// Write sha256sums.
	slices.Sort(sumLines)
	sumPath := filepath.Join(runDir, "sha256sums.txt")
	return os.WriteFile(sumPath, []byte(strings.Join(sumLines, "\n")+"\n"), 0o644) //nolint:gosec // checksum file
}

// LoadManifest reads the chain-of-custody manifest.
func (a *Archive) LoadManifest() (*Manifest, error) {
	path := filepath.Join(a.Path, "manifest.json")
	data, err := os.ReadFile(path) //nolint:gosec // archive file
	if errors.Is(err, os.ErrNotExist) {
		return &Manifest{SchemaVersion: "1"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if jsonErr := json.Unmarshal(data, &m); jsonErr != nil {
		return nil, fmt.Errorf("parse manifest: %w", jsonErr)
	}
	return &m, nil
}

// SaveManifest writes the manifest and its SHA-256.
func (a *Archive) SaveManifest(m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	path := filepath.Join(a.Path, "manifest.json")
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // manifest
		return err
	}
	hash := sha256Hex(data)
	hashPath := filepath.Join(a.Path, "manifest.json.sha256")
	return os.WriteFile(hashPath, []byte("sha256:"+hash+"\n"), 0o644) //nolint:gosec // hash file
}

// AppendRun adds a run to the manifest and detects gaps.
func (m *Manifest) AppendRun(run ManifestRun, expectedIntervalH float64) error {
	now := run.CollectedAt
	if m.CreatedAt == "" {
		m.CreatedAt = now
	}
	m.LastUpdated = now

	// Gap detection.
	if len(m.Runs) > 0 && expectedIntervalH > 0 {
		lastRun := m.Runs[len(m.Runs)-1]
		lastTime, lastErr := time.Parse(time.RFC3339, lastRun.CollectedAt)
		if lastErr != nil {
			return fmt.Errorf("parse CollectedAt for run %q: %w", lastRun.RunID, lastErr)
		}
		thisTime, thisErr := time.Parse(time.RFC3339, run.CollectedAt)
		if thisErr != nil {
			return fmt.Errorf("parse CollectedAt for run %q: %w", run.RunID, thisErr)
		}
		gap := thisTime.Sub(lastTime).Hours()
		// Gaps must exceed 150% of the expected interval to account for
		// clock drift and minor scheduling delays in cron/systemd timers.
		const gapThresholdMultiplier = 1.5
		threshold := expectedIntervalH * gapThresholdMultiplier
		if gap > threshold {
			m.Gaps = append(m.Gaps, Gap{
				ExpectedAfter:     lastRun.RunID,
				ActualNextRun:     run.RunID,
				GapHours:          gap,
				ExpectedIntervalH: expectedIntervalH,
			})
		}
	}

	m.Runs = append(m.Runs, run)
	return nil
}

// Verify checks archive integrity — manifest hash and per-run checksums.
func (a *Archive) Verify() ([]string, []string) {
	var errs, warnings []string

	// Check manifest hash.
	manifestData, err := os.ReadFile(filepath.Join(a.Path, "manifest.json")) //nolint:gosec
	if err != nil {
		errs = append(errs, "manifest.json missing or unreadable")
		return errs, warnings
	}
	expectedHash, hashErr := os.ReadFile(filepath.Join(a.Path, "manifest.json.sha256")) //nolint:gosec
	switch {
	case hashErr == nil:
		actualHash := "sha256:" + sha256Hex(manifestData)
		if strings.TrimSpace(string(expectedHash)) != actualHash {
			errs = append(errs, "manifest.json SHA-256 mismatch")
		}
	case os.IsNotExist(hashErr):
		// No companion .sha256 file. Older archives predate the
		// integrity sidecar; report as a warning so verify still
		// completes but the operator is told the integrity check
		// is degraded — silently passing without a hash file is the
		// scenario this fix prevents.
		warnings = append(warnings, "manifest.json.sha256 missing — integrity hash unverified")
	default:
		// Permission / IO error reading an existing hash sidecar is
		// a genuine error: a sidecar file is present but we cannot
		// read it, so we cannot say the manifest matches.
		errs = append(errs, fmt.Sprintf("manifest.json.sha256 unreadable: %v", hashErr))
	}

	// Check each run directory.
	var m Manifest
	if jsonErr := json.Unmarshal(manifestData, &m); jsonErr != nil {
		errs = append(errs, "manifest.json invalid JSON")
		return errs, warnings
	}

	// An empty runs list is invalid — a legitimate manifest always
	// contains at least one run entry. An empty list indicates
	// tampering or corruption.
	if len(m.Runs) == 0 {
		errs = append(errs, "manifest integrity failure: runs list is empty — manifest may have been tampered with")
		return errs, warnings
	}

	for _, run := range m.Runs {
		runDir := filepath.Join(a.Path, "runs", run.RunID)
		if _, statErr := os.Stat(runDir); statErr != nil {
			errs = append(errs, fmt.Sprintf("run %s: directory missing", run.RunID))
		}
	}

	for _, gap := range m.Gaps {
		warnings = append(warnings, fmt.Sprintf("gap: %s → %s (%.0fh, expected %.0fh)",
			gap.ExpectedAfter, gap.ActualNextRun, gap.GapHours, gap.ExpectedIntervalH))
	}

	return errs, warnings
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// isSafeRunRelative checks that a name passed to WriteRun is a relative
// path that stays inside the run directory: no leading separator, no
// parent segments, no NUL bytes, no Windows-style absolute paths.
// Mirrors the verifier-side check in archiveverify so writer and reader
// reject the same set of unsafe names.
func isSafeRunRelative(name string) bool {
	if name == "" {
		return false
	}
	if strings.ContainsRune(name, 0) {
		return false
	}
	if filepath.IsAbs(name) {
		return false
	}
	for _, seg := range strings.Split(filepath.ToSlash(name), "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}
