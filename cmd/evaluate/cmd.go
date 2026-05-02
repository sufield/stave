// Package evaluate implements the stave evaluate command for running
// compliance profile evaluation against observation snapshots. Supports
// the HIPAA profile with compound risk detection, acknowledged exceptions,
// and text/JSON report output.
package evaluate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	ui "github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/compliance"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/profile"
	"github.com/sufield/stave/internal/profile/exception"
	"github.com/sufield/stave/internal/profile/reporter"
)

// options holds the raw CLI flag values for the evaluate command.
type options struct {
	SnapshotPath string
	ProfileID    string
	Format       appcontracts.OutputFormat
	OutputPath   string
}

// NewCmd constructs the evaluate command.
func NewCmd() *cobra.Command {
	opts := &options{
		Format: appcontracts.FormatText,
	}

	cmd := &cobra.Command{
		Use:     "evaluate",
		Aliases: []string{"eval"},
		Short:   "Evaluate a snapshot against a compliance profile",
		Long: `Evaluate runs all controls in a compliance profile against an observation
snapshot and produces a report with findings, remediation steps, and
compliance citations.

Exit Codes:
  0   All CRITICAL controls pass
  1   One or more CRITICAL controls fail
  2   Input or configuration error`,
		Example: `  stave evaluate --snapshot observations/snap.json --profile hipaa
  stave evaluate --snapshot snap.json --profile hipaa --format json --output report.json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) (runErr error) {
			w, closer, err := resolveOutput(opts.OutputPath, cmd.OutOrStdout())
			if err != nil {
				return fmt.Errorf("open output: %w", err)
			}
			defer closer(&runErr)
			return run(w, opts)
		},
	}

	cmd.Flags().StringVar(&opts.SnapshotPath, "snapshot", "", "Path to observation snapshot JSON (required)")
	cmd.Flags().StringVar(&opts.ProfileID, "profile", "", "Compliance profile ID (required)")
	cmd.Flags().VarP(&opts.Format, "format", "f", "Output format: text or json")
	cmd.Flags().StringVarP(&opts.OutputPath, "output", "o", "", "Output file path (default: stdout)")

	_ = cmd.MarkFlagRequired("snapshot")
	_ = cmd.MarkFlagRequired("profile")

	return cmd
}

func run(w io.Writer, opts *options) error {
	// Load snapshot. A missing or malformed snapshot file is a user
	// input failure, not an internal error — wrap as ui.UserError so
	// the global ExitCode classifier maps it to ExitInputError (=2).
	snap, err := loadSnapshot(opts.SnapshotPath)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load snapshot: %w", err)}
	}

	// Validate schema version.
	if schemaErr := validateSchema(snap.SchemaVersion); schemaErr != nil {
		return &ui.UserError{Err: fmt.Errorf("validate schema: %w", schemaErr)}
	}

	// Load profile.
	prof, err := profile.LoadProfile(opts.ProfileID)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load profile: %w", err)}
	}

	// Evaluate.
	report, err := prof.Evaluate(snap, allRegistries()...)
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}

	// Load and apply exceptions from project root stave.yaml.
	// stave.yaml is optional — its absence is the common case for
	// projects that haven't yet acknowledged any findings, and must
	// not turn `stave evaluate` into a hard failure. LoadExceptions
	// already returns (nil, nil) on ErrNotExist, but guard at the
	// call site too so a future change to the loader cannot turn the
	// missing-file case back into a fatal error silently.
	staveYAML := "stave.yaml"
	excs, excErr := exception.LoadExceptions(staveYAML)
	if excErr != nil {
		if errors.Is(excErr, os.ErrNotExist) {
			slog.Debug("no exceptions file found; continuing with empty exception list", "path", staveYAML)
			excs = nil
		} else {
			return fmt.Errorf("load exceptions: %w", excErr)
		}
	}
	if len(excs) > 0 {
		acks := exception.ApplyExceptions(excs, report.Results, extractBucketName(snap), time.Now())
		// Only valid exceptions belong in the public Acknowledged list.
		// Previously, invalid acks (where the compensating control
		// wasn't in place) were also appended, making it look as if
		// the user had successfully acknowledged a finding that
		// remained un-mitigated.
		validAcks := make(map[string]struct{}, len(acks))
		for i := range acks {
			ack := &acks[i]
			if !ack.IsValid() {
				continue
			}
			validAcks[string(ack.ControlID)] = struct{}{}
			report.Acknowledged = append(report.Acknowledged, profile.AcknowledgedEntry{
				ControlID:      ack.ControlID,
				Bucket:         ack.Bucket,
				Rationale:      ack.Rationale,
				AcknowledgedBy: ack.AcknowledgedBy,
				Valid:          ack.Valid,
				InvalidReason:  string(ack.InvalidReason),
				InvalidDetail:  ack.InvalidDetail,
			})
		}

		// Re-evaluate compound findings: a compound risk whose
		// TriggerIDs are all covered by valid acknowledged exceptions
		// is no longer an active risk. The filter rule lives on
		// Report.FilterUnacknowledgedCompound so cmd/evaluate stops
		// open-coding the trigger-set walk.
		report.FilterUnacknowledgedCompound(validAcks)
	}

	// Recount FailCounts and Pass from the final filtered results,
	// regardless of whether exceptions were applied. The earlier
	// shape only ran this recount inside the `len(excs) > 0` block,
	// so a profile evaluation without exceptions silently used the
	// stale FailCounts that prof.Evaluate computed before any
	// post-processing — including before compound findings were
	// folded in. The exit-code check downstream then read the
	// stale count and could pass a run that had compound findings
	// at higher severity than any single control's verdict.
	report.Recount()

	// Build metadata. A zero CapturedAt would render as
	// "0001-01-01T00:00:00Z" — Go's zero-time is a valid wall-clock
	// instant in the year 1, indistinguishable from a real but
	// ancient observation. Surface a warning so an upstream producer
	// emitting unset captured_at fields is visible rather than
	// silently flowing through every report.
	if snap.CapturedAt.IsZero() {
		slog.Warn("snapshot has zero captured_at; report timestamp will render as 0001-01-01T00:00:00Z",
			"bucket", extractBucketName(snap),
			"account", extractAccountID(snap),
		)
	}
	meta := reporter.ReportMeta{
		BucketName: extractBucketName(snap),
		AccountID:  extractAccountID(snap),
		Timestamp:  snap.CapturedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}

	// Select reporter.
	format, fmtErr := ui.ParseOutputFormat(string(opts.Format))
	if fmtErr != nil {
		return fmtErr
	}
	rep, repErr := reporter.New(string(format))
	if repErr != nil {
		return repErr
	}

	if err := rep.Write(w, report, meta); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	// Exit code: gate on CRITICAL per-control failures *and* on any
	// active compound (chain) finding regardless of severity. The
	// previous gate only checked SeverityCritical, which let
	// chain-detected compound risks (e.g. two High controls combining
	// into a Critical kill-chain) pass CI even though the
	// CompoundFindings list captured the chain. Any chain that
	// reached the active list is by definition above the noise
	// threshold the chain catalog encoded — exit non-zero so CI
	// blocks the release.
	criticalCount := report.CriticalFailureCount()
	compoundCount := report.CompoundCount()
	if report.HasCriticalFailures() || report.HasCompoundFindings() {
		var msg string
		switch {
		case criticalCount > 0 && compoundCount > 0:
			msg = fmt.Sprintf("%d CRITICAL control(s) failed and %d compound risk chain(s) active",
				criticalCount, compoundCount)
		case criticalCount > 0:
			msg = fmt.Sprintf("%d CRITICAL control(s) failed", criticalCount)
		default:
			msg = fmt.Sprintf("%d compound risk chain(s) active", compoundCount)
		}
		// Wrap with ui.ErrSecurityAuditFindings so the global
		// handleExecutionError routing maps this to ExitSecurity (=1)
		// and renders it through the standard error reporter. The
		// previous private exitError type duplicated that mapping
		// inside this package and short-circuited the global error
		// renderer, so two paths drifted out of sync over time.
		return fmt.Errorf("%w: %s", ui.ErrSecurityAuditFindings, msg)
	}

	return nil
}

// ExitCode returns the exit code from an evaluate error, delegating
// to the global ui.ExitCode classifier so the evaluate command
// participates in the same exit-code map as every other command.
func ExitCode(err error) int {
	return ui.ExitCode(err)
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

func allRegistries() []*compliance.ControlCatalog {
	return []*compliance.ControlCatalog{
		compliance.GetControlRegistry(),
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
	for i := range snap.Assets {
		parts := strings.Split(string(snap.Assets[i].ID), ":")
		if len(parts) >= 5 && parts[4] != "" {
			return parts[4]
		}
	}
	return ""
}

// resolveOutput returns the destination writer and a closer that
// surfaces close errors instead of silently swallowing them. The
// closer accepts the run's outer error pointer; when the run
// succeeded but Close failed (typically a flush-on-close write
// failure against a slow disk or broken pipe), the close error
// becomes the run's error so the caller does not exit 0 with a
// truncated file on disk.
func resolveOutput(path string, stdout io.Writer) (io.Writer, func(*error), error) {
	if path == "" {
		return stdout, func(*error) {}, nil
	}
	// SafeCreateFile rejects symlinks at the destination path by
	// default (resists symlink-attack on a writable directory) and
	// uses 0o600 perms so a finding artifact written to a shared
	// host doesn't leak through world-readable defaults. Overwrite
	// is allowed because re-running `stave evaluate` over the same
	// output file is a normal workflow.
	opts := fsutil.DefaultWriteOpts()
	opts.Overwrite = true
	f, err := fsutil.SafeCreateFile(fsutil.CleanUserPath(path), opts)
	if err != nil {
		return nil, nil, err
	}
	return f, func(outErr *error) {
		closeErr := f.Close()
		if outErr != nil && *outErr == nil {
			*outErr = closeErr
		}
	}, nil
}
