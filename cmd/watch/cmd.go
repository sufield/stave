// Package watch implements the 'stave watch' command for continuous
// integrity monitoring. Watches an observation directory for new
// snapshots and runs assessment on each change.
package watch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/adapters/alert"
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/app/watch"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/ports"
)

// watchAssessment is the partial wire-shape of stave apply's JSON
// output that the watch loop consumes. RiskSignals.Status
// deserialises into the domain risk.ThresholdStatus so the
// "OVERDUE" check routes through the typed predicate
// (ThresholdStatus.IsOverdue) instead of repeating the magic
// literal here.
type watchAssessment struct {
	Status  string `json:"status"`
	Summary struct {
		Violations int `json:"violations"`
	} `json:"summary"`
	RiskSignals  []watchRiskSignal `json:"risk_signals"`
	TopExposures []struct {
		ControlID string  `json:"control_id"`
		DaysBlind float64 `json:"days_blind"`
	} `json:"top_exposures"`
	Findings []struct {
		ControlID string `json:"control_id"`
		AssetID   string `json:"asset_id"`
	} `json:"findings"`
}

// watchRiskSignal is the partial wire-shape of a single risk_signals
// entry. Embeds risk.ThresholdStatus directly so the watch loop
// asks the typed status its IsOverdue predicate without re-binding
// the magic vocabulary.
type watchRiskSignal struct {
	Status risk.ThresholdStatus `json:"status"`
}

type options struct {
	ControlsDir     string
	ObservationsDir string
	Interval        time.Duration
	MaxUnsafe       string
	Sinks           []string
	AllowUnknown    bool
	TeamManifest    string
}

// NewCmd constructs the top-level watch command.
func NewCmd() *cobra.Command {
	opts := &options{
		Interval: time.Hour,
		Sinks:    []string{"stdout"},
	}

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Continuously monitor observations for security regressions",
		Long: `Watch monitors an observation directory for new snapshots and runs
assessment on each change. Detects security regressions, recoveries,
and degradation in real time. Emits alerts to configurable sinks.

This turns Stave from a testing tool into a continuous integrity monitor.
The extractor drops JSON snapshots into the observations directory; Stave
detects the change, runs assessment, and alerts if the safety envelope
has degraded.

Inputs:
  --controls, -i       Path to control definitions directory
  --observations, -o   Path to observation snapshots directory
  --interval           Polling interval as fallback (default: 1h)
  --max-unsafe         Maximum allowed unsafe duration (e.g., 168h)
  --sink               Alert sinks: stdout, file:<path> (repeatable)

Outputs:
  Alert sinks          One-line summaries (stdout) or JSONL (file)

Exit Codes:
  0   Clean shutdown via SIGINT/SIGTERM
  2   Input or configuration error
  4   Internal error`,
		Example: `  stave watch --controls ./controls --observations ./observations
  stave watch -i ./controls -o ./observations --interval 5m --sink file:alerts.jsonl
  stave watch -i ./controls -o ./observations --sink stdout --sink file:/var/log/stave.jsonl`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}

	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "Path to control definitions directory")
	cmd.Flags().StringVarP(&opts.ObservationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	cmd.Flags().DurationVar(&opts.Interval, "interval", opts.Interval, "Polling interval (default: 1h)")
	cmd.Flags().StringVar(&opts.MaxUnsafe, "max-unsafe", "168h", "Maximum allowed unsafe duration")
	cmd.Flags().StringSliceVar(&opts.Sinks, "sink", opts.Sinks, "Alert sinks: stdout, file:<path>")
	cmd.Flags().BoolVar(&opts.AllowUnknown, "allow-unknown-input", false, "Allow unknown observation source types")
	cmd.Flags().StringVar(&opts.TeamManifest, "team-manifest", "", "Path to stave-teams.yaml for owner routing on alerts")

	return cmd
}

func run(ctx context.Context, stdout, stderr io.Writer, opts *options) error {
	// Validate inputs.
	if _, err := os.Stat(opts.ControlsDir); err != nil {
		return fmt.Errorf("controls directory: %w", err)
	}
	if _, err := os.Stat(opts.ObservationsDir); err != nil {
		return fmt.Errorf("observations directory: %w", err)
	}

	// Build sinks.
	sinks, err := buildSinks(stdout, opts.Sinks)
	if err != nil {
		return err
	}

	// Find stave binary for self-invocation.
	binary, err := resolveExecutable()
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	fmt.Fprintf(stderr, "Watching %s (interval: %s, sinks: %v)\n", opts.ObservationsDir, opts.Interval, opts.Sinks)

	assessFn := buildAssessFunc(binary, opts)

	cfg := watch.Config{
		ObservationsDir: opts.ObservationsDir,
		Interval:        opts.Interval,
		Sinks:           sinks,
		Assess:          assessFn,
		Logger:          logger,
		Clock:           ports.RealClock{},
	}

	// Load team manifest for owner-annotated alerts.
	if opts.TeamManifest != "" {
		manifest, tmErr := teams.LoadManifest(opts.TeamManifest)
		if tmErr != nil {
			return fmt.Errorf("load team manifest: %w", tmErr)
		}
		cfg.OwnerResolver = &manifestResolver{manifest: manifest}
	}

	monitor := watch.New(cfg)

	return monitor.Run(ctx)
}

// buildAssessFunc creates an assessment function that shells out to
// 'stave apply --format json' and parses the result. This reuses
// 100% of the evaluation pipeline without deep coupling.
func buildAssessFunc(binary string, opts *options) watch.AssessFunc {
	return func(ctx context.Context) (state string, violations int, slaBreaches int, maxDwellHours float64, violationIDs []string, err error) {
		args := []string{
			"apply",
			"--controls", opts.ControlsDir,
			"--observations", opts.ObservationsDir,
			"--max-unsafe", opts.MaxUnsafe,
			"--now", time.Now().UTC().Format(time.RFC3339),
			"--format", "json",
			"--quiet",
		}
		if opts.AllowUnknown {
			args = append(args, "--allow-unknown-input")
		}

		cmd := exec.CommandContext(ctx, binary, args...) //nolint:gosec // validated: absolute path, symlinks resolved, regular file confirmed
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		runErr := cmd.Run()

		// Parse JSON output even on exit code 3 (violations found).
		if stdout.Len() == 0 {
			if runErr != nil {
				return "", 0, 0, 0, nil, fmt.Errorf("assessment failed: %s", stderr.String())
			}
			return "COMPLIANT", 0, 0, 0, nil, nil
		}

		var result watchAssessment

		if jsonErr := json.Unmarshal(stdout.Bytes(), &result); jsonErr != nil {
			return "", 0, 0, 0, nil, fmt.Errorf("parse assessment output: %w", jsonErr)
		}

		// Count SLA breaches via the domain ThresholdStatus.IsOverdue
		// predicate so the OVERDUE vocabulary stays on the typed
		// status, not in the watch decode.
		for i := range result.RiskSignals {
			if result.RiskSignals[i].Status.IsOverdue() {
				slaBreaches++
			}
		}

		// Max dwell time from top exposures.
		for _, te := range result.TopExposures {
			if te.DaysBlind*24 > maxDwellHours {
				maxDwellHours = te.DaysBlind * 24
			}
		}

		// Violation IDs (control:asset pairs for regression detection).
		for _, f := range result.Findings {
			violationIDs = append(violationIDs, f.ControlID+":"+f.AssetID)
		}

		return result.Status, result.Summary.Violations, slaBreaches, maxDwellHours, violationIDs, nil
	}
}

func buildSinks(stdout io.Writer, specs []string) ([]ports.AlertSink, error) {
	var sinks []ports.AlertSink
	for _, spec := range specs {
		switch {
		case spec == "stdout":
			sinks = append(sinks, &alert.StdoutSink{W: stdout})
		case strings.HasPrefix(spec, "file:"):
			path := strings.TrimPrefix(spec, "file:")
			sinks = append(sinks, &alert.FileSink{Path: path})
		case spec == "syslog" || strings.HasPrefix(spec, "syslog:"):
			facility := "local0"
			if after, ok := strings.CutPrefix(spec, "syslog:"); ok {
				facility = after
			}
			pri, parseErr := alert.ParseSyslogFacility(facility)
			if parseErr != nil {
				return nil, parseErr
			}
			sink, sysErr := alert.NewSyslogSink(pri, "stave")
			if sysErr != nil {
				return nil, sysErr
			}
			sinks = append(sinks, sink)
		case strings.HasPrefix(spec, "cef:"):
			path := strings.TrimPrefix(spec, "cef:")
			sink, cefErr := alert.NewCEFFileSink(path)
			if cefErr != nil {
				return nil, cefErr
			}
			sinks = append(sinks, sink)
		default:
			return nil, fmt.Errorf("unknown sink: %q (use stdout, file:<path>, syslog, syslog:<facility>, or cef:<path>)", spec)
		}
	}
	if len(sinks) == 0 {
		sinks = append(sinks, &alert.StdoutSink{W: stdout})
	}
	return sinks, nil
}

// resolveExecutable returns a validated absolute path to the current
// binary for safe self-invocation. It resolves symlinks and verifies
// the result is an absolute path to a regular file.
func resolveExecutable() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot determine executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return "", fmt.Errorf("resolving executable path: %w", err)
	}
	if !filepath.IsAbs(execPath) {
		return "", fmt.Errorf("executable path %q is not absolute — refusing self-invocation", execPath)
	}
	info, err := os.Stat(execPath)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("executable path %q is not a regular file — refusing self-invocation", execPath)
	}
	return execPath, nil
}

// manifestResolver implements watch.OwnerResolver using a team manifest.
type manifestResolver struct {
	manifest *teams.Manifest
}

func (r *manifestResolver) ResolveViolation(violationID string) (teamID, teamName, contact, slack, jira string) {
	// violationID is "controlID:assetID". A missing separator means
	// the producer emitted a malformed ID — log it and skip ownership
	// resolution rather than passing the whole string as the asset ID
	// (which would mis-route alerts to whichever owner happens to
	// match a sloppy prefix).
	controlID, assetID, found := strings.Cut(violationID, ":")
	if !found {
		slog.Warn("watch: skipping ownership resolution for malformed violation_id (missing ':' separator)",
			"violation_id", violationID)
		return "", "", "", "", ""
	}
	owner := r.manifest.ResolveOwner(nil, assetID, controlID)
	team := r.manifest.TeamByID(owner.TeamID)
	if team != nil {
		return owner.TeamID, owner.TeamName, owner.Contact, team.Routing.SlackChannel, team.Routing.JiraProject
	}
	return owner.TeamID, owner.TeamName, owner.Contact, "", ""
}
