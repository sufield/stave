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

// InventoryReport is the top-level output.
type InventoryReport struct {
	GeneratedAt     time.Time        `json:"generated_at"`
	ObservationsDir string           `json:"observations_dir"`
	RetentionDays   int              `json:"retention_days"`
	Summary         InventorySummary `json:"summary"`
	Snapshots       []SnapshotEntry  `json:"snapshots"`
}

// InventorySummary aggregates counts by action.
type InventorySummary struct {
	TotalFiles         int   `json:"total_files"`
	TotalSizeBytes     int64 `json:"total_size_bytes"`
	RecommendedKeep    int   `json:"recommended_keep"`
	RecommendedArchive int   `json:"recommended_archive"`
	RecommendedDelete  int   `json:"recommended_delete"`
	RecommendedReview  int   `json:"recommended_review"`
}

// SnapshotEntry is per-file inventory data.
type SnapshotEntry struct {
	Path                    string    `json:"path"`
	CapturedAt              time.Time `json:"captured_at"`
	FileSizeBytes           int64     `json:"file_size_bytes"`
	AssetCount              int       `json:"asset_count"`
	AgeHours                float64   `json:"age_hours"`
	Assessed                bool      `json:"assessed"`
	QualityPass             bool      `json:"quality_pass"`
	RetentionEligible       bool      `json:"retention_eligible"`
	RecommendedAction       string    `json:"recommended_action"`
	RecommendedActionReason string    `json:"recommended_action_reason"`
}

func runInventory(w io.Writer, opts *inventoryOptions) error {
	entries, err := os.ReadDir(opts.ObservationsDir)
	if err != nil {
		return fmt.Errorf("read observations directory: %w", err)
	}

	now := time.Now().UTC()
	retentionThreshold := time.Duration(opts.RetentionDays) * 24 * time.Hour

	var snapshots []SnapshotEntry
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

	report := InventoryReport{
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

func buildSnapshotEntry(path string, now time.Time, retentionThreshold time.Duration, minAssets int) *SnapshotEntry {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}

	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil
	}

	var snap asset.Snapshot
	if jsonErr := json.Unmarshal(data, &snap); jsonErr != nil {
		return nil
	}

	if snap.SchemaVersion != kernel.SchemaObservation && snap.SchemaVersion != "obs.v1" {
		return nil
	}

	capturedAt := snap.CapturedAt
	if capturedAt.IsZero() {
		capturedAt = info.ModTime()
	}

	ageHours := now.Sub(capturedAt).Hours()
	assetCount := len(snap.Assets)
	retentionEligible := now.Sub(capturedAt) > retentionThreshold
	qualityPass := assetCount >= minAssets
	assessed := checkAssessed(path)

	action, reason := recommendAction(retentionEligible, qualityPass, assessed)

	return &SnapshotEntry{
		Path:                    path,
		CapturedAt:              capturedAt,
		FileSizeBytes:           info.Size(),
		AssetCount:              assetCount,
		AgeHours:                ageHours,
		Assessed:                assessed,
		QualityPass:             qualityPass,
		RetentionEligible:       retentionEligible,
		RecommendedAction:       action,
		RecommendedActionReason: reason,
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

func computeSummary(snapshots []SnapshotEntry) InventorySummary {
	var s InventorySummary
	s.TotalFiles = len(snapshots)
	for i := range snapshots {
		s.TotalSizeBytes += snapshots[i].FileSizeBytes
		switch snapshots[i].RecommendedAction {
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

func renderInventoryJSON(w io.Writer, r *InventoryReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func renderInventoryTable(w io.Writer, r *InventoryReport) error { //nolint:unparam // error return for format-dispatch consistency
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
		age := fmt.Sprintf("%.0fd", s.AgeHours/24)
		assessed := "NO"
		if s.Assessed {
			assessed = "YES"
		}
		quality := "FAIL"
		if s.QualityPass {
			quality = "PASS"
		}
		fmt.Fprintf(w, "%-35s %-8s %-7d %-9s %-8s %s\n",
			filepath.Base(s.Path), age, s.AssetCount, assessed, quality, s.RecommendedAction)
	}
	return nil
}

func renderInventoryOpenMetrics(w io.Writer, r *InventoryReport) error { //nolint:unparam // error return for format-dispatch consistency
	tsMs := r.GeneratedAt.UnixMilli()

	fmt.Fprintln(w, "# HELP stave_snapshot_count Total snapshot files by recommended action")
	fmt.Fprintln(w, "# TYPE stave_snapshot_count gauge")
	for _, action := range []string{"keep", "archive", "delete", "review"} {
		count := 0
		for i := range r.Snapshots {
			if r.Snapshots[i].RecommendedAction == action {
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
			if r.Snapshots[i].RecommendedAction == action {
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
