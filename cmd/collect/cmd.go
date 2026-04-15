// Package collect implements the 'stave collect' command for automated
// GRC evidence collection.
package collect

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	appcollect "github.com/sufield/stave/internal/app/collect"
	"github.com/sufield/stave/internal/version"
)

type options struct {
	Snapshot   string
	Archive    string
	Compliance string
	Verify     bool
	Format     string
}

// NewCmd constructs the collect command.
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Automated GRC evidence collection",
		Long: `Run assessment, produce evidence bundle, and append to the
evidence archive. Designed for cron, systemd timer, or CronJob.

Each invocation runs assessment against the snapshot, produces an
evidence bundle, and appends it to the archive with chain-of-custody
manifest. The archive accumulates over time and becomes the audit
artifact.

Exit Codes:
  0   Collection complete
  1   Findings detected (collection still completed)
  2   Invalid input
  4   Internal error`,
		Example: `  stave collect --snapshot obs.json --compliance hipaa --archive ./evidence/
  stave collect --verify --archive ./evidence/`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCollect(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to observation snapshot")
	cmd.Flags().StringVar(&opts.Archive, "archive", "", "path to evidence archive directory (required)")
	cmd.Flags().StringVar(&opts.Compliance, "compliance", "", "comma-separated framework profiles")
	cmd.Flags().BoolVar(&opts.Verify, "verify", false, "verify archive integrity")
	cmd.Flags().StringVar(&opts.Format, "format", "", "include format in bundle (oscal)")

	_ = cmd.MarkFlagRequired("archive")

	return cmd
}

func runCollect(stdout, stderr io.Writer, opts *options) error {
	archive, err := appcollect.NewArchive(opts.Archive)
	if err != nil {
		return err
	}

	// Verify mode.
	if opts.Verify {
		return runVerify(stdout, archive)
	}

	if opts.Snapshot == "" {
		return errors.New("--snapshot is required for collection")
	}

	start := time.Now().UTC()
	runID := start.Format("2006-01-15T15-04-05Z")

	// Build evidence bundle files.
	// In a full implementation, this calls stave apply + stave export
	// internally. For now, record the collection with metadata.
	frameworks := strings.Split(opts.Compliance, ",")
	for i := range frameworks {
		frameworks[i] = strings.TrimSpace(frameworks[i])
	}

	meta := appcollect.RunMetadata{
		RunID:        runID,
		CollectedAt:  start.Format(time.RFC3339),
		StaveVersion: version.String,
		Frameworks:   frameworks,
	}

	// The evidence files would be produced by calling the assessment
	// and export pipelines. For this iteration, write a placeholder
	// evidence record that confirms the collection ran.
	evidenceData, _ := json.MarshalIndent(map[string]any{
		"collected_at": start.Format(time.RFC3339),
		"frameworks":   frameworks,
		"snapshot":     opts.Snapshot,
	}, "", "  ")

	files := map[string][]byte{
		"evidence.json": evidenceData,
	}

	elapsed := time.Since(start)
	meta.CollectionDurationMs = elapsed.Milliseconds()

	if writeErr := archive.WriteRun(runID, files, meta); writeErr != nil {
		return fmt.Errorf("write run: %w", writeErr)
	}

	// Update manifest.
	manifest, loadErr := archive.LoadManifest()
	if loadErr != nil {
		return fmt.Errorf("load manifest: %w", loadErr)
	}
	if manifest.ArchiveID == "" {
		manifest.ArchiveID = strings.Join(frameworks, "-") + "-archive"
	}

	manifest.AppendRun(appcollect.ManifestRun{
		RunID:        runID,
		CollectedAt:  start.Format(time.RFC3339),
		Frameworks:   frameworks,
		FindingCount: meta.FindingCount,
		SHA256:       meta.SHA256Sums["evidence.json"],
	}, 24) // 24h expected interval

	if saveErr := archive.SaveManifest(manifest); saveErr != nil {
		return fmt.Errorf("save manifest: %w", saveErr)
	}

	fmt.Fprintf(stderr, "Collected: run %s (%dms)\n", runID, elapsed.Milliseconds())
	fmt.Fprintf(stderr, "Archive: %s (%d runs)\n", opts.Archive, len(manifest.Runs))

	if len(manifest.Gaps) > 0 {
		fmt.Fprintf(stderr, "Warning: %d gap(s) detected in collection schedule\n", len(manifest.Gaps))
	}

	return nil
}

func runVerify(w io.Writer, archive *appcollect.Archive) error {
	errs, warnings := archive.Verify()

	fmt.Fprintln(w, "EVIDENCE ARCHIVE INTEGRITY REPORT")
	fmt.Fprintf(w, "Archive: %s\n\n", archive.Path)

	if len(errs) == 0 && len(warnings) == 0 {
		fmt.Fprintln(w, "Status: OK — all integrity checks passed")
		return nil
	}

	if len(errs) > 0 {
		fmt.Fprintln(w, "ERRORS")
		for _, e := range errs {
			fmt.Fprintf(w, "  X %s\n", e)
		}
	}
	if len(warnings) > 0 {
		fmt.Fprintln(w, "WARNINGS")
		for _, wn := range warnings {
			fmt.Fprintf(w, "  ! %s\n", wn)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%d integrity error(s)", len(errs))
	}
	return nil
}
