// Package evaluate implements the stave evaluate command for running
// compliance profile evaluation against observation snapshots. Supports
// the HIPAA profile with compound risk detection, acknowledged exceptions,
// and text/JSON report output.
package evaluate

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/hipaa"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/profile"
	"github.com/sufield/stave/internal/profile/exception"
	"github.com/sufield/stave/internal/profile/reporter"
)

// options holds the raw CLI flag values for the evaluate command.
type options struct {
	SnapshotPath string
	ProfileID    string
	Format       string
	OutputPath   string
}

// NewCmd constructs the evaluate command.
func NewCmd() *cobra.Command {
	opts := &options{
		Format: "text",
	}

	cmd := &cobra.Command{
		Use:   "evaluate",
		Short: "Evaluate a snapshot against a compliance profile",
		Long: `Evaluate runs all invariants in a compliance profile against an observation
snapshot and produces a report with findings, remediation steps, and
compliance citations.

Exit Codes:
  0   All CRITICAL invariants pass
  1   One or more CRITICAL invariants fail
  2   Input or configuration error`,
		Example: `  stave evaluate --snapshot observations/snap.json --profile hipaa
  stave evaluate --snapshot snap.json --profile hipaa --format json --output report.json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w, closer, err := resolveOutput(opts.OutputPath, cmd.OutOrStdout())
			if err != nil {
				return fmt.Errorf("open output: %w", err)
			}
			defer closer()
			return run(w, opts)
		},
	}

	cmd.Flags().StringVar(&opts.SnapshotPath, "snapshot", "", "Path to observation snapshot JSON (required)")
	cmd.Flags().StringVar(&opts.ProfileID, "profile", "", "Compliance profile ID (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", opts.Format, "Output format: text or json")
	cmd.Flags().StringVarP(&opts.OutputPath, "output", "o", "", "Output file path (default: stdout)")

	_ = cmd.MarkFlagRequired("snapshot")
	_ = cmd.MarkFlagRequired("profile")

	return cmd
}

func run(w io.Writer, opts *options) error {
	// Load snapshot.
	snap, err := loadSnapshot(opts.SnapshotPath)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}

	// Validate schema version.
	if schemaErr := validateSchema(snap.SchemaVersion); schemaErr != nil {
		return fmt.Errorf("validate schema: %w", schemaErr)
	}

	// Load profile.
	prof, err := profile.LoadProfile(opts.ProfileID)
	if err != nil {
		return fmt.Errorf("load profile: %w", err)
	}

	// Evaluate.
	report, err := prof.Evaluate(snap, allRegistries()...)
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}

	// Load and apply exceptions.
	staveYAML := filepath.Join(filepath.Dir(opts.SnapshotPath), "stave.yaml")
	excs, excErr := exception.LoadExceptions(staveYAML)
	if excErr != nil {
		return fmt.Errorf("load exceptions: %w", excErr)
	}
	if len(excs) > 0 {
		acks := exception.ApplyExceptions(excs, report.Results)
		for _, ack := range acks {
			report.Acknowledged = append(report.Acknowledged, profile.AcknowledgedEntry{
				ControlID:      ack.ControlID,
				Bucket:         ack.Bucket,
				Rationale:      ack.Rationale,
				AcknowledgedBy: ack.AcknowledgedBy,
				Valid:          ack.Valid,
				InvalidReason:  ack.InvalidReason,
			})
		}
		// Recount after exceptions.
		report.FailCounts = make(map[hipaa.Severity]int)
		report.Pass = true
		for _, r := range report.Results {
			if !r.Pass {
				report.FailCounts[r.Severity]++
				report.Pass = false
			}
		}
		if len(report.CompoundFindings) > 0 {
			report.Pass = false
		}
	}

	// Build metadata.
	meta := reporter.ReportMeta{
		BucketName: extractBucketName(snap),
		AccountID:  extractAccountID(snap),
		Timestamp:  snap.CapturedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}

	// Select reporter.
	var rep reporter.Reporter
	switch opts.Format {
	case "json":
		rep = reporter.JSONReporter{}
	default:
		rep = reporter.TextReporter{}
	}

	if err := rep.Write(w, report, meta); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	// Exit code based on CRITICAL failures.
	if report.FailCounts[hipaa.Critical] > 0 {
		return &exitError{code: 1, msg: fmt.Sprintf("%d CRITICAL invariant(s) failed", report.FailCounts[hipaa.Critical])}
	}

	return nil
}

// exitError signals a non-zero exit code without being a "real" error
// for Cobra's error handling.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// ExitCode returns the exit code from an evaluate error, or 0 if nil.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exitError); ok {
		return ee.code
	}
	return 2
}

func loadSnapshot(path string) (asset.Snapshot, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from CLI flag
	if err != nil {
		return asset.Snapshot{}, fmt.Errorf("read %s: %w", path, err)
	}
	var snap asset.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return asset.Snapshot{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return snap, nil
}

func validateSchema(version kernel.Schema) error {
	if version != kernel.SchemaObservation {
		return fmt.Errorf("unsupported schema version %q (expected %s)", version, kernel.SchemaObservation)
	}
	return nil
}

func allRegistries() []*hipaa.Registry {
	return []*hipaa.Registry{
		hipaa.ControlRegistry,
	}
}

func extractBucketName(snap asset.Snapshot) string {
	for _, a := range snap.Assets {
		if name, ok := a.Properties["bucket_name"].(string); ok {
			return name
		}
	}
	if len(snap.Assets) > 0 {
		return string(snap.Assets[0].ID)
	}
	return "unknown"
}

func extractAccountID(snap asset.Snapshot) string {
	// Try to extract from ARN: arn:aws:s3:::bucket → no account.
	// For now return a placeholder; real extraction depends on extractor.
	return "000000000000"
}

func resolveOutput(path string, stdout io.Writer) (io.Writer, func(), error) {
	if path == "" {
		return stdout, func() {}, nil
	}
	f, err := os.Create(path) //nolint:gosec // path from CLI flag
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}
