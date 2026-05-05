// Package collect implements the 'stave collect' command for automated
// GRC evidence collection.
package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	stavecel "github.com/sufield/stave/internal/adapters/cel"
	builtinctl "github.com/sufield/stave/internal/adapters/controls/builtin"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	appcollect "github.com/sufield/stave/internal/app/collect"
	appeval "github.com/sufield/stave/internal/app/eval"
	appscore "github.com/sufield/stave/internal/app/score"
	"github.com/sufield/stave/internal/controldata"
	"github.com/sufield/stave/internal/core/capabilities"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/version"
)

type options struct {
	Snapshot   string
	Archive    string
	Compliance string
	Verify     bool
	Format     string
	Daemon     bool
	Period     time.Duration
	PIDFile    string
	AuditLabel string
	MaxUnsafe  time.Duration
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
			if opts.Daemon {
				return runDaemon(cmd.Context(), cmd.ErrOrStderr(), opts)
			}
			return runCollect(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to observation snapshot")
	cmd.Flags().StringVar(&opts.Archive, "archive", "", "path to evidence archive directory (required)")
	cmd.Flags().StringVar(&opts.Compliance, "compliance", "", "comma-separated framework profiles")
	cmd.Flags().BoolVar(&opts.Verify, "verify", false, "verify archive integrity")
	cmd.Flags().StringVar(&opts.Format, "format", "", "include format in bundle (oscal)")
	cmd.Flags().BoolVar(&opts.Daemon, "daemon", false, "run as long-lived daemon collecting on --period interval")
	cmd.Flags().DurationVar(&opts.Period, "period", 24*time.Hour, "collection interval for daemon mode")
	cmd.Flags().StringVar(&opts.PIDFile, "pid-file", "", "path to PID file (daemon mode)")
	cmd.Flags().StringVar(&opts.AuditLabel, "audit-label", "", "label embedded in bundle metadata")
	// Match cmd/apply's default so an asset's tolerated-unsafe budget
	// is consistent across the collect / apply pair. Without this
	// flag the SLA threshold defaulted to zero, which made every
	// duration-based control fire on first observation.
	cmd.Flags().DurationVar(&opts.MaxUnsafe, "max-unsafe", 168*time.Hour, "maximum tolerated unsafe duration before a finding fires (default 168h)")

	cliflags.MustMarkRequired(cmd, "archive")

	// Status subcommand.
	statusOpts := &statusOptions{}
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show daemon status and evidence archive coverage",
		Long: `Show whether the collect daemon is running, the last collection
time, and evidence archive coverage with gap detection.

Exit Codes:
  0   Status reported
  2   Invalid input
  4   Internal error`,
		Example:       `  stave collect status --evidence-dir ./evidence/ --pid-file /var/run/stave.pid`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := appcollect.RunStatus(appcollect.StatusOpts{
				EvidenceDir: statusOpts.EvidenceDir,
				PIDFile:     statusOpts.PIDFile,
			})
			_, err := fmt.Fprint(cmd.OutOrStdout(), out)
			return err
		},
	}
	statusCmd.Flags().StringVar(&statusOpts.EvidenceDir, "evidence-dir", "", "evidence archive directory")
	statusCmd.Flags().StringVar(&statusOpts.PIDFile, "pid-file", "", "PID file path")
	cmd.AddCommand(statusCmd)

	return cmd
}

type statusOptions struct {
	EvidenceDir string
	PIDFile     string
}

func runDaemon(ctx context.Context, stderr io.Writer, opts *options) error {
	if opts.Snapshot == "" {
		return errors.New("--snapshot is required for daemon mode")
	}

	return appcollect.RunDaemon(ctx, appcollect.DaemonOpts{
		Period:     opts.Period,
		PIDFile:    opts.PIDFile,
		AuditLabel: opts.AuditLabel,
		RunOnce: func(innerCtx context.Context) error {
			return runCollect(innerCtx, io.Discard, stderr, opts)
		},
	})
}

func runCollect(ctx context.Context, stdout, stderr io.Writer, opts *options) error {
	archive, err := appcollect.NewArchive(opts.Archive)
	if err != nil {
		return err
	}

	if opts.Verify {
		return runVerify(stdout, archive)
	}

	if opts.Snapshot == "" {
		return errors.New("--snapshot is required for collection")
	}

	start := time.Now().UTC()
	runID := start.Format("2006-01-02T15-04-05Z")

	// Treat an empty / whitespace-only --compliance flag as "no
	// frameworks" rather than producing a one-element slice with an
	// empty string. The earlier shape passed [""] downstream, which
	// the framework-profile loader silently treated as "use the
	// default profile" — a misleading no-op when the operator
	// genuinely intended to disable compliance reporting.
	var frameworks []string
	if trimmed := strings.TrimSpace(opts.Compliance); trimmed != "" {
		for _, part := range strings.Split(trimmed, ",") {
			if name := strings.TrimSpace(part); name != "" {
				frameworks = append(frameworks, name)
			}
		}
	}
	if frameworks == nil {
		frameworks = []string{}
	}

	// Load snapshot.
	snapshots, err := observations.LoadBundle(opts.Snapshot)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}
	if len(snapshots) == 0 {
		return errors.New("snapshot contains no observations")
	}

	// Load controls.
	store := builtinctl.NewControlStore(controldata.FS, ".")
	controls, err := store.All()
	if err != nil {
		return fmt.Errorf("load controls: %w", err)
	}

	// Load chains.
	chains, chainsErr := ctlyaml.LoadChains("chains", capabilities.Builtin())
	if chainsErr != nil {
		return fmt.Errorf("loading chains: %w", chainsErr)
	}

	// CEL evaluator.
	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		return fmt.Errorf("init CEL: %w", err)
	}

	// Run assessment.
	result, evalErr := appeval.EvaluateLoaded(ctx, appeval.EvaluationRequest{
		Controls:          controls,
		Snapshots:         snapshots,
		MaxUnsafeDuration: opts.MaxUnsafe,
		Clock:             ports.RealClock{},
		Hasher:            crypto.NewHasher(),
		StaveVersion:      version.String,
		PredicateParser:   ctlyaml.ParsePredicate,
		CELEvaluator:      celEval,
	})
	if evalErr != nil {
		return fmt.Errorf("assessment: %w", evalErr)
	}

	// Enrich with chains.
	appeval.EnrichReport(&result, controls, chains)

	// Serialize assessment output.
	assessmentData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal assessment: %w", err)
	}

	// Count findings by severity.
	sevCounts := result.CountBySeverity()
	criticalCount := sevCounts.Critical
	highCount := sevCounts.High

	// Compute posture score. SLA totals come from the report so the
	// loop below only handles the remediation.Finding projection.
	slaTotal, slaBreached := result.SLASummary()
	hasSLA := slaTotal > 0
	remFindings := make([]remediation.Finding, len(result.Findings))
	for i := range result.Findings {
		remFindings[i] = remediation.Finding{Finding: result.Findings[i]}
	}
	scoreResult := appscore.Compute(appscore.Input{
		Findings:       remFindings,
		ChainFindings:  result.ChainFindings,
		ChainDefs:      len(chains),
		MaxChainWeight: appscore.ChainMaxWeight(chains),
		SLABreached:    slaBreached,
		SLATotal:       slaTotal,
		HasSLA:         hasSLA,
		Weights:        appscore.DefaultWeights(),
		GeneratedAt:    start,
	})

	files := map[string][]byte{
		"assessment.json": assessmentData,
	}

	elapsed := time.Since(start)
	// Compute the assessment.json SHA-256 here so the caller-side
	// meta carries the hash before AppendRun reads it. WriteRun
	// receives RunMetadata by value and computes its own checksum
	// table for the per-run sha256sums.txt artifact, but the local
	// copy never propagated back to the caller's manifest entry —
	// the previous shape passed an empty SHA into AppendRun, which
	// produced a manifest with no integrity hash for the run.
	assessmentHash := "sha256:" + string(crypto.HashBytes(assessmentData))
	meta := appcollect.RunMetadata{
		RunID:                runID,
		CollectedAt:          start.Format(time.RFC3339),
		StaveVersion:         version.String,
		Frameworks:           frameworks,
		FindingCount:         len(result.Findings),
		CriticalCount:        criticalCount,
		HighCount:            highCount,
		PostureScore:         &scoreResult.Score,
		PostureScoreRubric:   scoreResult.RubricBand,
		CollectionDurationMs: elapsed.Milliseconds(),
		SHA256Sums:           map[string]string{"assessment.json": assessmentHash},
	}

	if writeErr := archive.WriteRun(runID, files, meta); writeErr != nil {
		return fmt.Errorf("write run: %w", writeErr)
	}

	// Update manifest.
	manifest, loadErr := archive.LoadManifest()
	if loadErr != nil {
		return fmt.Errorf("load manifest: %w", loadErr)
	}
	if manifest.ArchiveID == "" {
		// strings.Join on an empty slice produces "", which would
		// land us at the malformed "-archive". Substitute a named
		// placeholder so the manifest's ArchiveID stays meaningful
		// even when the operator runs collect without an explicit
		// --compliance flag.
		joined := strings.Join(frameworks, "-")
		if joined == "" {
			joined = "default"
		}
		manifest.ArchiveID = joined + "-archive"
	}

	if appendErr := manifest.AppendRun(appcollect.ManifestRun{
		RunID:        runID,
		CollectedAt:  start.Format(time.RFC3339),
		Frameworks:   frameworks,
		FindingCount: len(result.Findings),
		SHA256:       meta.SHA256Sums["assessment.json"],
	}, 24); appendErr != nil {
		return fmt.Errorf("append run to manifest: %w", appendErr)
	}

	if saveErr := archive.SaveManifest(manifest); saveErr != nil {
		return fmt.Errorf("save manifest: %w", saveErr)
	}

	// Status output: route through a sticky-error writer so a broken
	// pipe (operator pipes stderr to head, etc.) propagates rather
	// than silently dropping later lines. The previous shape ignored
	// every Fprintf return.
	sw := &stickyStderr{w: stderr}
	fmt.Fprintf(sw, "Collected: run %s (%dms, %d findings)\n", runID, elapsed.Milliseconds(), len(result.Findings))
	fmt.Fprintf(sw, "Archive: %s (%d runs)\n", opts.Archive, len(manifest.Runs))

	if len(manifest.Gaps) > 0 {
		fmt.Fprintf(sw, "Warning: %d gap(s) detected in collection schedule\n", len(manifest.Gaps))
	}

	return sw.err
}

// stickyStderr captures the first write error so subsequent fmt.Fprintf
// calls become no-ops. Mirrors the stickyWriter pattern in
// internal/app/archiveverify/format.go and internal/profile/reporter/text.go.
type stickyStderr struct {
	w   io.Writer
	err error
}

func (s *stickyStderr) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.w.Write(p)
	if err != nil {
		s.err = err
	}
	return n, err
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
