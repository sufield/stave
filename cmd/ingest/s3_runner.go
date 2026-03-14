package ingest

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	s3 "github.com/sufield/stave/internal/adapters/input/extract/s3"
	s3snapshot "github.com/sufield/stave/internal/adapters/input/extract/s3/snapshot"
	appingest "github.com/sufield/stave/internal/app/ingest"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/platform/observations"
	"github.com/sufield/stave/internal/sanitize"
)

// S3Config defines the resolved parameters for an AWS S3 ingestion run.
type S3Config struct {
	InputDir        string
	OutFile         string
	Now             time.Time
	ScopeConfig     *s3.ScopeConfig
	Scrub           bool
	Force           bool
	DryRun          bool
	TextOutput      bool
	AllowSymlinkOut bool
}

// S3Runner orchestrates the conversion of AWS CLI S3 exports into Stave observations.
type S3Runner struct {
	UI     *ui.Runtime
	Clock  ports.Clock
	Stdout io.Writer
}

// Run executes the S3 ingestion workflow.
func (r *S3Runner) Run(ctx context.Context, cfg S3Config) error {
	snapshots, err := r.extract(ctx, cfg)
	if err != nil {
		return err
	}

	if len(snapshots) == 0 || len(snapshots[0].Assets) == 0 {
		return r.handleEmpty(cfg)
	}

	if cfg.DryRun {
		if cfg.TextOutput {
			fmt.Fprintf(r.Stdout, "[dry-run] would write: %s\n", cfg.OutFile)
		}
		return nil
	}

	if err := r.persist(cfg, snapshots); err != nil {
		return err
	}

	if cfg.TextOutput {
		fmt.Fprintf(r.Stdout, "Extracted %d bucket(s) to %s\n", len(snapshots[0].Assets), cfg.OutFile)
		printIngestCoverage(r.Stdout, snapshots[len(snapshots)-1].Assets)
	}
	return nil
}

func (r *S3Runner) extract(ctx context.Context, cfg S3Config) ([]asset.Snapshot, error) {
	extractor := s3snapshot.NewSnapshotExtractor(cfg.ScopeConfig)

	done := r.UI.BeginProgress("ingest snapshot into normalized observations")
	defer done()

	return appingest.ExtractS3Snapshots(appingest.S3IngestExtractRequest{
		Context:     ctx,
		SnapshotDir: cfg.InputDir,
		Now:         cfg.Now,
		Extract: func(ctx context.Context, snapshotDir string, now time.Time) ([]asset.Snapshot, error) {
			return extractor.ExtractFromSnapshotWithTime(ctx, snapshotDir, now)
		},
	})
}

func (r *S3Runner) persist(cfg S3Config, snapshots []asset.Snapshot) error {
	req := appingest.ObservationsWriteRequest{
		Path:         cfg.OutFile,
		Snapshots:    snapshots,
		Overwrite:    cfg.Force,
		AllowSymlink: cfg.AllowSymlinkOut,
		Writer:       observations.JSONWriter{},
	}
	if cfg.Scrub {
		req.Scrubber = sanitize.New()
	}
	return appingest.WriteObservationsFile(req)
}

func (r *S3Runner) handleEmpty(cfg S3Config) error {
	if cfg.TextOutput {
		fmt.Fprintln(r.Stdout, "No S3 buckets matching health scope found in snapshot")
	}
	if cfg.DryRun {
		if cfg.TextOutput {
			fmt.Fprintf(r.Stdout, "[dry-run] would write: %s\n", cfg.OutFile)
		}
		return nil
	}
	return r.persist(cfg, nil)
}

// --- Coverage Reporting ---

// evidenceShortLabel extracts a short label from an evidence or missing_inputs string.
// "tags from get-bucket-tagging/foo.json" -> "tags"
// "policy from get-bucket-policy/foo.json" -> "policy"
// "get-bucket-policy/foo.json" -> "policy" (missing_inputs format)
func evidenceShortLabel(s string) string {
	if idx := strings.Index(s, " from "); idx > 0 {
		return s[:idx]
	}
	s = filepath.Base(filepath.Dir(s))
	if after, ok := strings.CutPrefix(s, "get-bucket-"); ok {
		return after
	}
	if after, ok := strings.CutPrefix(s, "get-"); ok {
		return after
	}
	return s
}

// printIngestCoverage writes a per-bucket input coverage summary to w.
func printIngestCoverage(w io.Writer, resources []asset.Asset) {
	if len(resources) == 0 {
		return
	}
	if optionalIngestInputCount("aws-s3") == 0 {
		return
	}

	fmt.Fprintln(w, "Input coverage:")

	for _, r := range resources {
		props := r.Properties
		foundLabels := extractIngestLabels(props, "evidence", true)
		missingLabels := extractIngestLabels(props, "missing_inputs", false)

		found := len(foundLabels)
		total := found + len(missingLabels)
		if total == 0 {
			continue
		}

		line := fmt.Sprintf("  %-24s %d/%d  %s", r.ID, found, total, strings.Join(foundLabels, ", "))
		if len(missingLabels) > 0 {
			line += fmt.Sprintf(" (missing: %s)", strings.Join(missingLabels, ", "))
		}
		fmt.Fprintln(w, line)
	}
}

func optionalIngestInputCount(profileName string) int {
	totalOptional := 0
	for _, p := range AllProfiles() {
		if string(p.Name) != profileName {
			continue
		}
		for _, inp := range p.Inputs {
			if !inp.Required {
				totalOptional++
			}
		}
		break
	}
	return totalOptional
}

func extractIngestLabels(props map[string]any, key string, skipRequiredListBuckets bool) []string {
	var labels []string
	appendLabel := func(raw string) {
		label := evidenceShortLabel(raw)
		if skipRequiredListBuckets && label == "list-buckets" {
			return
		}
		labels = append(labels, label)
	}

	switch values := props[key].(type) {
	case []string:
		for _, value := range values {
			appendLabel(value)
		}
	case []any:
		for _, value := range values {
			s, ok := value.(string)
			if !ok {
				continue
			}
			appendLabel(s)
		}
	}
	return labels
}
