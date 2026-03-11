package ingest

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	s3 "github.com/sufield/stave/internal/adapters/input/extract/s3"
	s3snapshot "github.com/sufield/stave/internal/adapters/input/extract/s3/snapshot"
	appingest "github.com/sufield/stave/internal/app/ingest"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/observations"
	"github.com/sufield/stave/internal/sanitize"
)

type s3Runner struct {
	runtime *ui.Runtime
	opts    *Options
}

type s3RunConfig struct {
	now         time.Time
	snapshotDir string
	outFile     string
	scopeConfig *s3.ScopeConfig
}

func newS3Runner(rt *ui.Runtime, opts *Options) *s3Runner {
	return &s3Runner{runtime: rt, opts: opts}
}

func (r *s3Runner) run(cmd *cobra.Command) error {
	cfg, err := r.prepareRun(cmd)
	if err != nil {
		return err
	}

	snapshots, err := r.extractSnapshots(cmd.Context(), cfg)
	if err != nil {
		return err
	}

	return r.persistOutput(cmd, cfg, snapshots)
}

func (r *s3Runner) prepareRun(cmd *cobra.Command) (s3RunConfig, error) {
	if r.opts.OutDir != "" && cmd.Flags().Changed("out") {
		return s3RunConfig{}, fmt.Errorf("--out and --out-dir are mutually exclusive")
	}

	snapshotDir := fsutil.CleanUserPath(r.opts.InputDir)
	scopeFile := fsutil.CleanUserPath(r.opts.ScopeFile)
	outFile := fsutil.CleanUserPath(r.opts.OutFile)
	outDir := fsutil.CleanUserPath(r.opts.OutDir)

	now, parseErr := compose.ResolveNow(r.opts.Now)
	if parseErr != nil {
		return s3RunConfig{}, parseErr
	}

	if outDir != "" {
		mkdirErr := fsutil.SafeMkdirAll(outDir, fsutil.WriteOptions{Perm: 0o700, AllowSymlink: cmdutil.AllowSymlinkOutEnabled(cmd)})
		if mkdirErr != nil {
			return s3RunConfig{}, fmt.Errorf("create --out-dir: %w", mkdirErr)
		}
		outFile = filepath.Join(outDir, now.UTC().Format(time.RFC3339)+".json")
	}

	writableErr := ensureOutputWritable(outFile, r.opts.Force || cmdutil.ForceEnabled(cmd), r.opts.DryRun)
	if writableErr != nil {
		return s3RunConfig{}, writableErr
	}
	inputErr := validateInputDir(snapshotDir)
	if inputErr != nil {
		return s3RunConfig{}, inputErr
	}

	scopeConfig, scopeErr := resolveScopeConfig(r.opts.IncludeAll, r.opts.BucketAllowlist, scopeFile)
	if scopeErr != nil {
		return s3RunConfig{}, scopeErr
	}

	return s3RunConfig{
		now:         now,
		snapshotDir: snapshotDir,
		outFile:     outFile,
		scopeConfig: scopeConfig,
	}, nil
}

func ensureOutputWritable(path string, overwrite, dryRun bool) error {
	if overwrite || dryRun {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("output file already exists: %s (use --force to overwrite)", path)
	}
	return nil
}

func validateInputDir(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("--input not accessible: %s: %w", path, err)
	}
	return nil
}

func resolveScopeConfig(includeAll bool, bucketAllowlist []string, scopeFile string) (*s3.ScopeConfig, error) {
	if includeAll {
		return &s3.ScopeConfig{IncludeAll: true}, nil
	}
	if len(bucketAllowlist) > 0 {
		return s3.NewScopeConfigFromAllowlist(bucketAllowlist), nil
	}
	if scopeFile != "" {
		cfg, err := s3.NewScopeConfigFromFile(scopeFile)
		if err != nil {
			return nil, fmt.Errorf("--scope file error: %w", err)
		}
		return cfg, nil
	}
	return s3.DefaultScopeConfig(), nil
}

func (r *s3Runner) extractSnapshots(ctx context.Context, cfg s3RunConfig) ([]asset.Snapshot, error) {
	extractor := s3snapshot.NewSnapshotExtractor(cfg.scopeConfig)
	done := r.runtime.BeginProgress("ingest snapshot into normalized observations")
	defer done()

	snapshots, err := appingest.ExtractS3Snapshots(appingest.S3IngestExtractRequest{
		Context:     ctx,
		SnapshotDir: cfg.snapshotDir,
		Now:         cfg.now,
		Extract: func(ctx context.Context, snapshotDir string, now time.Time) ([]asset.Snapshot, error) {
			return extractor.ExtractFromSnapshotWithTime(ctx, snapshotDir, now)
		},
	})
	if err != nil {
		return nil, err
	}
	return snapshots, nil
}

func (r *s3Runner) persistOutput(cmd *cobra.Command, cfg s3RunConfig, snapshots []asset.Snapshot) error {
	if len(snapshots) == 0 || len(snapshots[0].Assets) == 0 {
		return r.handleEmptySnapshot(cmd, cfg)
	}

	if r.opts.DryRun {
		if cmdutil.TextOutputEnabled(cmd) {
			fmt.Fprintf(cmd.OutOrStdout(), "[dry-run] would write: %s\n", cfg.outFile)
		}
		return nil
	}

	if err := r.writeObservationsFile(cmd, cfg.outFile, snapshots); err != nil {
		return err
	}

	if cmdutil.TextOutputEnabled(cmd) {
		fmt.Fprintf(cmd.OutOrStdout(), "Extracted %d bucket(s) to %s\n", len(snapshots[0].Assets), cfg.outFile)
		printIngestCoverage(cmd.OutOrStdout(), snapshots[len(snapshots)-1].Assets)
	}
	return nil
}

func (r *s3Runner) handleEmptySnapshot(cmd *cobra.Command, cfg s3RunConfig) error {
	if cmdutil.TextOutputEnabled(cmd) {
		fmt.Fprintln(cmd.OutOrStdout(), "No S3 buckets matching health scope found in snapshot")
	}
	if r.opts.DryRun {
		if cmdutil.TextOutputEnabled(cmd) {
			fmt.Fprintf(cmd.OutOrStdout(), "[dry-run] would write: %s\n", cfg.outFile)
		}
		return nil
	}
	return r.writeObservationsFile(cmd, cfg.outFile, nil)
}

func (r *s3Runner) writeObservationsFile(cmd *cobra.Command, path string, snapshots []asset.Snapshot) error {
	req := appingest.ObservationsWriteRequest{
		Path:         path,
		Snapshots:    snapshots,
		Overwrite:    r.opts.Force || cmdutil.ForceEnabled(cmd),
		AllowSymlink: cmdutil.AllowSymlinkOutEnabled(cmd),
		Writer: func(p string, snaps []asset.Snapshot, overwrite, allowSymlink bool) error {
			return observations.WriteJSON(observations.WriteRequest{
				Path:          p,
				SchemaVersion: kernel.SchemaObservation,
				Snapshots:     snaps,
				Overwrite:     overwrite,
				AllowSymlink:  allowSymlink,
			})
		},
	}
	if r.opts.Scrub {
		s := sanitize.New()
		req.Scrubber = s.ScrubSnapshot
	}
	return appingest.WriteObservationsFile(req)
}

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
	for _, p := range ingestProfiles {
		if p.Name != profileName {
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
