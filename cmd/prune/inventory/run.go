package inventory

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// inventoryReport is the top-level output.
type inventoryReport struct {
	GeneratedAt     time.Time        `json:"generated_at"`
	ObservationsDir string           `json:"observations_dir"`
	RetentionDays   int              `json:"retention_days"`
	Summary         inventorySummary `json:"summary"`
	Snapshots       []snapshotEntry  `json:"snapshots"`
}

// inventorySummary aggregates counts by action.
type inventorySummary struct {
	TotalFiles         int   `json:"total_files"`
	TotalSizeBytes     int64 `json:"total_size_bytes"`
	RecommendedKeep    int   `json:"recommended_keep"`
	RecommendedArchive int   `json:"recommended_archive"`
	RecommendedDelete  int   `json:"recommended_delete"`
	RecommendedReview  int   `json:"recommended_review"`
}

// snapshotEntry is per-file inventory data. The JSON shape is the
// stable contract documented in
// docs/contracts/snapshot-inventory.schema.json — additive
// changes only.
type snapshotEntry struct {
	FilePath          string    `json:"file_path"`
	AssetID           string    `json:"asset_id"`
	AssetType         string    `json:"asset_type"`
	CapturedAt        time.Time `json:"captured_at"`
	Age               string    `json:"age"`
	AgeSeconds        int64     `json:"age_seconds"`
	Tier              string    `json:"tier"`
	FileSizeBytes     int64     `json:"file_size_bytes"`
	AssetCount        int       `json:"asset_count"`
	SchemaValid       bool      `json:"schema_valid"`
	AssessmentStatus  string    `json:"assessment_status"`
	QualityPass       bool      `json:"quality_pass"`
	QualityWarnings   []string  `json:"quality_warnings"`
	RetentionEligible bool      `json:"retention_eligible"`
	Action            string    `json:"action"`
	Reason            string    `json:"reason"`
}

func runInventory(w io.Writer, opts *inventoryOptions) error {
	entries, err := os.ReadDir(opts.ObservationsDir)
	if err != nil {
		return fmt.Errorf("read observations directory: %w", err)
	}

	now := time.Now().UTC()
	retentionThreshold := time.Duration(opts.RetentionDays) * 24 * time.Hour

	var snapshots []snapshotEntry
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(opts.ObservationsDir, entry.Name())
		se := buildSnapshotEntry(path, now, retentionThreshold, opts.MinAssetCount)
		if se != nil {
			snapshots = append(snapshots, *se)
		}
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].CapturedAt.After(snapshots[j].CapturedAt)
	})

	report := inventoryReport{
		GeneratedAt:     now,
		ObservationsDir: opts.ObservationsDir,
		RetentionDays:   opts.RetentionDays,
		Snapshots:       snapshots,
	}
	report.Summary = computeSummary(snapshots)

	out := w
	if opts.Out != "" {
		f, fileErr := os.Create(opts.Out)
		if fileErr != nil {
			return fmt.Errorf("create output file: %w", fileErr)
		}
		defer f.Close()
		out = f
	}

	switch opts.Format {
	case "json":
		return renderInventoryJSON(out, &report)
	case "openmetrics":
		return renderInventoryOpenMetrics(out, &report)
	default:
		return renderInventoryTable(out, &report)
	}
}

func buildSnapshotEntry(path string, now time.Time, retentionThreshold time.Duration, minAssets int) *snapshotEntry {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	absPath, absErr := filepath.Abs(path)
	if absErr != nil {
		absPath = path
	}

	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil
	}

	var snap asset.Snapshot
	schemaValid := true
	if jsonErr := json.Unmarshal(data, &snap); jsonErr != nil {
		// Malformed JSON: keep the entry but flag schema_valid=false
		// so external tools see the file rather than silently dropping
		// it. The contract requires schema_valid; returning nil hid the
		// problem.
		return &snapshotEntry{
			FilePath:         absPath,
			FileSizeBytes:    info.Size(),
			SchemaValid:      false,
			AssessmentStatus: "unknown",
			QualityWarnings:  []string{"malformed JSON: " + jsonErr.Error()},
			Action:           "review",
			Reason:           "malformed JSON — investigate before integrating",
		}
	}

	if snap.SchemaVersion != kernel.SchemaObservation && snap.SchemaVersion != "obs.v1" {
		schemaValid = false
	}

	capturedAt := snap.CapturedAt
	if capturedAt.IsZero() {
		capturedAt = info.ModTime()
	}

	ageDur := now.Sub(capturedAt)
	if ageDur < 0 {
		ageDur = 0
	}
	ageSeconds := int64(ageDur.Seconds())
	assetCount := len(snap.Assets)
	retentionEligible := now.Sub(capturedAt) > retentionThreshold
	qualityPass := assetCount >= minAssets
	assessed := checkAssessed(path)

	action, reason := recommendAction(retentionEligible, qualityPass, assessed)
	if !schemaValid {
		// Force "review" for unknown-schema observations so the operator
		// inspects them before the external tool acts.
		action, reason = "review", "unrecognised schema_version — verify before integrating"
	}

	var assetID, assetType string
	if assetCount > 0 {
		assetID = snap.Assets[0].ID.String()
		assetType = string(snap.Assets[0].Type)
	}

	return &snapshotEntry{
		FilePath:          absPath,
		AssetID:           assetID,
		AssetType:         assetType,
		CapturedAt:        capturedAt,
		Age:               formatAge(ageSeconds),
		AgeSeconds:        ageSeconds,
		Tier:              "", // tier resolution belongs to plan; inventory's per-file tier is unset.
		FileSizeBytes:     info.Size(),
		AssetCount:        assetCount,
		SchemaValid:       schemaValid,
		AssessmentStatus:  assessmentStatus(assessed),
		QualityPass:       qualityPass,
		QualityWarnings:   buildQualityWarnings(qualityPass, minAssets, assetCount),
		RetentionEligible: retentionEligible,
		Action:            action,
		Reason:            reason,
	}
}

// assessmentStatus maps the boolean assessed signal to the closed
// vocabulary the contract advertises.
func assessmentStatus(assessed bool) string {
	if assessed {
		return "evaluated"
	}
	return "pending"
}

// buildQualityWarnings produces the per-snapshot quality_warnings
// list. Returns an empty slice (never nil) so consumers don't need
// to handle null vs []string.
func buildQualityWarnings(qualityPass bool, minAssets, assetCount int) []string {
	out := make([]string, 0)
	if !qualityPass {
		out = append(out, fmt.Sprintf("low asset count: %d < %d minimum", assetCount, minAssets))
	}
	return out
}

// formatAge renders a non-negative age in seconds as the contract's
// human-readable `age` field. Mirrors snapplan.formatAge so the two
// commands emit the same vocabulary.
func formatAge(seconds int64) string {
	const day = 24 * 60 * 60
	const hour = 60 * 60
	const minute = 60
	switch {
	case seconds >= day:
		return fmt.Sprintf("%dd", seconds/day)
	case seconds >= hour:
		return fmt.Sprintf("%dh", seconds/hour)
	case seconds >= minute:
		return fmt.Sprintf("%dm", seconds/minute)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}

// checkAssessed looks for a corresponding output file (same base name with .out.json extension).
func checkAssessed(snapshotPath string) bool {
	base := strings.TrimSuffix(filepath.Base(snapshotPath), filepath.Ext(snapshotPath))
	dir := filepath.Dir(snapshotPath)

	candidates := []string{
		filepath.Join(dir, base+".out.json"),
		filepath.Join(dir, "..", "output", base+".json"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return true
		}
	}
	return false
}

func recommendAction(retentionEligible, qualityPass, assessed bool) (string, string) {
	switch {
	case !retentionEligible && qualityPass:
		return "keep", "within retention window and quality passes"
	case !retentionEligible && !qualityPass:
		return "review", "within retention window but quality fails — investigate"
	case retentionEligible && qualityPass:
		return "archive", "past retention window, quality passes — safe to archive"
	case retentionEligible && !qualityPass && !assessed:
		return "delete", "past retention window, quality fails, never assessed"
	case retentionEligible && !qualityPass:
		return "delete", "past retention window, quality fails"
	default:
		return "review", "unable to determine recommendation"
	}
}

func computeSummary(snapshots []snapshotEntry) inventorySummary {
	var s inventorySummary
	s.TotalFiles = len(snapshots)
	for i := range snapshots {
		s.TotalSizeBytes += snapshots[i].FileSizeBytes
		switch snapshots[i].Action {
		case "keep":
			s.RecommendedKeep++
		case "archive":
			s.RecommendedArchive++
		case "delete":
			s.RecommendedDelete++
		case "review":
			s.RecommendedReview++
		}
	}
	return s
}

func renderInventoryJSON(w io.Writer, r *inventoryReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func renderInventoryTable(w io.Writer, r *inventoryReport) error { //nolint:unparam // error return for format-dispatch consistency
	totalMB := float64(r.Summary.TotalSizeBytes) / (1024 * 1024)
	fmt.Fprintln(w, "SNAPSHOT INVENTORY")
	fmt.Fprintf(w, "Directory: %s  |  Retention: %d days  |  %d files  (%.0f MB)\n\n",
		r.ObservationsDir, r.RetentionDays, r.Summary.TotalFiles, totalMB)

	fmt.Fprintf(w, "SUMMARY\n  Keep: %d   Archive: %d   Delete: %d   Review: %d\n\n",
		r.Summary.RecommendedKeep, r.Summary.RecommendedArchive,
		r.Summary.RecommendedDelete, r.Summary.RecommendedReview)

	sep := strings.Repeat("-", 90)
	fmt.Fprintln(w, "SNAPSHOTS")
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "%-35s %-8s %-7s %-9s %-8s %s\n", "Path", "Age", "Assets", "Assessed", "Quality", "Action")
	fmt.Fprintln(w, sep)

	for i := range r.Snapshots {
		s := &r.Snapshots[i]
		assessed := "NO"
		if s.AssessmentStatus == "evaluated" {
			assessed = "YES"
		}
		quality := "FAIL"
		if s.QualityPass {
			quality = "PASS"
		}
		fmt.Fprintf(w, "%-35s %-8s %-7d %-9s %-8s %s\n",
			filepath.Base(s.FilePath), s.Age, s.AssetCount, assessed, quality, s.Action)
	}
	return nil
}

func renderInventoryOpenMetrics(w io.Writer, r *inventoryReport) error { //nolint:unparam // error return for format-dispatch consistency
	tsMs := r.GeneratedAt.UnixMilli()

	fmt.Fprintln(w, "# HELP stave_snapshot_count Total snapshot files by recommended action")
	fmt.Fprintln(w, "# TYPE stave_snapshot_count gauge")
	for _, action := range []string{"keep", "archive", "delete", "review"} {
		count := 0
		for i := range r.Snapshots {
			if r.Snapshots[i].Action == action {
				count++
			}
		}
		if count > 0 {
			fmt.Fprintf(w, "stave_snapshot_count{action=%q} %d %d\n", action, count, tsMs)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "# HELP stave_snapshot_size_bytes Total size of snapshot files by action")
	fmt.Fprintln(w, "# TYPE stave_snapshot_size_bytes gauge")
	for _, action := range []string{"keep", "archive", "delete", "review"} {
		var size int64
		for i := range r.Snapshots {
			if r.Snapshots[i].Action == action {
				size += r.Snapshots[i].FileSizeBytes
			}
		}
		if size > 0 {
			fmt.Fprintf(w, "stave_snapshot_size_bytes{action=%q} %d %d\n", action, size, tsMs)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# EOF")
	return nil
}
