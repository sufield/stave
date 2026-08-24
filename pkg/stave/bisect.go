package stave

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	appbisect "github.com/sufield/stave/internal/app/bisect"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/engine"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// BisectInput carries the inputs for [BisectControl]. Logger receives
// snapshot-archive load diagnostics.
type BisectInput struct {
	ControlsDir string
	ObsDir      string
	ControlID   string
	Mode        string
	Format      string
	EvalTime    string
	ResourceARN asset.ID
	Logger      *slog.Logger
}

// BisectOutput carries the rendered result of [BisectControl]: the report
// (Stdout), any warnings (Stderr), and whether the text render found a
// violation window (the caller maps that to exit 3 — JSON output never
// gates, preserving the prior behaviour).
type BisectOutput struct {
	Stdout        []byte
	Stderr        []byte
	HasViolations bool
}

// BisectControl binary-searches (or linearly scans) a timestamped snapshot
// archive to find when a single control was first violated, and renders the
// transition report as "text"/"" or "json". An unknown format wraps
// [ErrInvalidInput] (exit 2); all other failures stay plain (exit 4). It is
// the library entry point behind `stave bisect`.
func BisectControl(ctx context.Context, in BisectInput) (BisectOutput, error) {
	mode, err := parseBisectMode(in.Mode)
	if err != nil {
		return BisectOutput{}, err
	}

	controlsDir := fsutil.CleanUserPath(in.ControlsDir)
	controls, err := loadControlsFromDir(ctx, controlsDir)
	if err != nil {
		return BisectOutput{}, err
	}

	targetID := kernel.ControlID(in.ControlID)
	target, found := appbisect.FindControl(controls, targetID)
	if !found {
		return BisectOutput{}, fmt.Errorf("control %s not found in %s", targetID, controlsDir)
	}

	snapshots, err := appbisect.LoadSnapshotDir(fsutil.CleanUserPath(in.ObsDir), fsutil.ReadFileLimited, in.Logger)
	if err != nil {
		return BisectOutput{}, fmt.Errorf("load snapshot directory: %w", err)
	}

	var clock ports.Clock = ports.RealClock{}
	if in.EvalTime != "" {
		t, parseErr := time.Parse(time.RFC3339, in.EvalTime)
		if parseErr != nil {
			return BisectOutput{}, fmt.Errorf("invalid --eval-time: %w", parseErr)
		}
		clock = ports.FixedClock(t)
	}

	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		return BisectOutput{}, fmt.Errorf("create CEL evaluator: %w", err)
	}

	evaluator := appbisect.MakeEvaluator(
		func(snaps []asset.Snapshot) (evaluation.ComplianceReport, error) {
			a := engine.NewAssessor(
				engine.WithControls([]policy.ControlDefinition{target}),
				engine.WithClock(clock),
				engine.WithHasher(crypto.NewHasher()),
				engine.WithPredicateEval(celEval),
				engine.WithPredicateParser(func(_ any) (*policy.UnsafePredicate, error) {
					return &policy.UnsafePredicate{}, nil
				}),
			)
			return a.Assess(ctx, snaps)
		},
		targetID,
		in.ResourceARN,
	)

	eng := &appbisect.Engine{Evaluate: evaluator}
	result, err := eng.Run(ctx, snapshots, mode, targetID, in.ResourceARN)
	if err != nil {
		return BisectOutput{}, fmt.Errorf("run bisect engine: %w", err)
	}

	return renderBisect(result, in.Format)
}

func parseBisectMode(s string) (appbisect.Mode, error) {
	switch s {
	case "bisect":
		return appbisect.Mode(0), nil // ModeBisect
	case "scan":
		return appbisect.Mode(1), nil // ModeScan
	default:
		return 0, fmt.Errorf("invalid --mode %q (supported: bisect, scan)", s)
	}
}

// renderBisect renders the bisect result. JSON goes to Stdout and never
// gates exit 3; text goes to Stdout (report) + Stderr (multi-window
// warning) and reports HasViolations. Split out for unit testing.
func renderBisect(result appbisect.Result, format string) (BisectOutput, error) {
	var stdout, stderr bytes.Buffer
	switch format {
	case "json":
		if err := jsonutil.WriteIndented(&stdout, result); err != nil {
			return BisectOutput{}, fmt.Errorf("write output: %w", err)
		}
		return BisectOutput{Stdout: stdout.Bytes()}, nil
	case "text", "":
		writeBisectText(&stdout, &stderr, result)
		return BisectOutput{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), HasViolations: result.HasViolation()}, nil
	default:
		return BisectOutput{}, fmt.Errorf("unknown format %q (valid: text, json): %w", format, ErrInvalidInput)
	}
}

func writeBisectText(stdout, stderr io.Writer, result appbisect.Result) {
	modeName := result.ModeLabel()

	if !result.HasViolation() {
		fmt.Fprintf(stdout, "%s COMPLETE: No violation found across %d snapshots.\n\n", modeName, result.SnapshotsTotal)
		fmt.Fprintf(stdout, "Control: %s has never been violated in this snapshot archive.\n", result.ControlID)
		return
	}

	fmt.Fprintf(stdout, "%s COMPLETE: %d violation window(s) found in %d steps (%d snapshots searched).\n\n",
		modeName, len(result.Windows), result.AssessmentsRun, result.SnapshotsTotal)
	fmt.Fprintf(stdout, "Control: %s\n", result.ControlID)
	if result.ResourceARN != "" {
		fmt.Fprintf(stdout, "Resource:  %s\n", result.ResourceARN)
	}
	fmt.Fprintln(stdout)

	for i, w := range result.Windows {
		if len(result.Windows) > 1 {
			label := ""
			if i == 0 {
				label = " (earliest)"
			}
			if w.IsOngoing {
				label = " (current)"
			}
			fmt.Fprintf(stdout, "Window %d%s:\n", i+1, label)
		}

		if w.EntryBefore.IsZero() {
			fmt.Fprintf(stdout, "  Violation predates the archive (present in earliest snapshot)\n")
			fmt.Fprintf(stdout, "  First observed: %s\n", w.EntryAfter.Format("2006-01-02T15:04:05Z"))
		} else {
			fmt.Fprintf(stdout, "  The change occurred between %s and %s.\n",
				w.EntryBefore.Format("2006-01-02T15:04:05Z"),
				w.EntryAfter.Format("2006-01-02T15:04:05Z"))
		}

		if w.IsOngoing {
			fmt.Fprintf(stdout, "  Status: ongoing (not yet remediated)\n")
		} else {
			fmt.Fprintf(stdout, "  Remediated between %s and %s.\n",
				w.ExitBefore.Format("2006-01-02T15:04:05Z"),
				w.ExitAfter.Format("2006-01-02T15:04:05Z"))
		}
		fmt.Fprintln(stdout)
	}

	if result.Delta != nil && len(result.Delta.Changes) > 0 {
		fmt.Fprintln(stdout, "State delta (between the two snapshots on either side of the transition):")
		fmt.Fprintln(stdout)
		for _, change := range result.Delta.Changes {
			for _, d := range change.Drifts {
				fmt.Fprintf(stdout, "  %-40s %v  →  %v\n", d.Attribute+":", d.OldValue, d.NewValue)
			}
		}
		fmt.Fprintln(stdout)
	}

	if result.ShouldWarnMultipleWindows() {
		fmt.Fprintln(stderr, "WARNING: Multiple violation windows detected in this snapshot range.")
		fmt.Fprintln(stderr, "         --mode bisect found the start of the current window only.")
		fmt.Fprintln(stderr, "         Run with --mode scan to find the earliest occurrence.")
		fmt.Fprintln(stderr)
	}

	if result.HasPatientZero() {
		fmt.Fprintf(stdout, "Patient Zero (earliest ever occurrence): Window 1\n")
	}

	fmt.Fprintln(stdout, strings.Repeat("-", 60))
	fmt.Fprintln(stdout, "Stave operates on snapshots. It cannot attribute changes to")
	fmt.Fprintln(stdout, "specific events within a window. To narrow the window, collect")
	fmt.Fprintln(stdout, "snapshots at higher frequency for this resource.")
}
