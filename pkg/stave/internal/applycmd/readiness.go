// Package applycmd is the engine behind `stave apply` (and the apply facade
// in pkg/stave). It owns the load -> compute -> render pipeline so the command
// stays a thin shell. cli/ui concerns (progress runtime, hints, exit routing)
// stay command-side.
package applycmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/sufield/stave/internal/app/readiness"
	schemaval "github.com/sufield/stave/internal/core/schemaval"
	"github.com/sufield/stave/internal/doctor"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// ReadinessRequest is the parsed input for `apply --dry-run`. MaxUnsafe and
// Now are pre-parsed stdlib types so the command constructs the request
// without the engine re-parsing flag strings.
type ReadinessRequest struct {
	ControlsDir            string
	ObservationsDir        string
	MaxUnsafe              time.Duration
	Now                    time.Time
	Sanitize               bool
	Format                 string // "text" | "json"
	ControlsFlagSet        bool
	HasEnabledControlPacks bool
}

// readinessJSONReport enriches the domain report with the CLI-specific
// next_command field for JSON output. The domain type omits this field
// because CLI command names are a presentation concern.
type readinessJSONReport struct {
	schemaval.ReadinessAssessment
	NextCommand string `json:"next_command"`
}

// AssessReadiness runs the readiness assessment (the `apply --dry-run`
// pipeline) and renders it to bytes. runEval is the validation closure built
// by pkg/stave from NewReadinessEvaluator. Returns the rendered report,
// whether the project is ready, and any error.
func AssessReadiness(req ReadinessRequest, runEval func(time.Duration, time.Time) (schemaval.EvaluationState, error)) ([]byte, bool, error) {
	prereqs, err := doctorPrereqs()
	if err != nil {
		return nil, false, err
	}

	report, err := readiness.AssessReadiness(schemaval.AssessmentContext{
		ControlSource:          req.ControlsDir,
		ObservationSource:      req.ObservationsDir,
		SLAThreshold:           req.MaxUnsafe,
		CurrentTime:            req.Now,
		ControlFlagsSet:        req.ControlsFlagSet,
		HasEnabledControlPacks: req.HasEnabledControlPacks,
		PreflightChecks:        prereqs,
		RunEvaluation:          runEval,
	})
	if err != nil {
		return nil, false, fmt.Errorf("assess readiness: %w", err)
	}

	out, err := renderReadiness(req.Format, report)
	if err != nil {
		return nil, false, err
	}
	return out, report.IsReady(), nil
}

// doctorPrereqs runs the shell-environment prerequisite checks. Replicates
// cmd/cmdutil/prereq.DoctorPrereqChecks (which stays command-side for other
// callers) using the same internal/doctor engine.
func doctorPrereqs() ([]schemaval.ValidationFinding, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve working directory: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable path: %w", err)
	}
	checks, _ := doctor.Run(&doctor.SystemEnvironment{Cwd: cwd, BinaryPath: exe})
	out := make([]schemaval.ValidationFinding, 0, len(checks))
	for _, c := range checks {
		out = append(out, schemaval.ValidationFinding{
			Name:        c.Name,
			Status:      c.Status,
			Message:     c.Message,
			Remediation: c.Remediation,
		})
	}
	return out, nil
}

// renderReadiness renders the readiness report as JSON or text.
func renderReadiness(format string, report schemaval.ReadinessAssessment) ([]byte, error) {
	var buf bytes.Buffer
	if format == "json" {
		if err := jsonutil.WriteIndented(&buf, readinessJSONReport{
			ReadinessAssessment: report,
			NextCommand:         report.NextCommand(),
		}); err != nil {
			return nil, fmt.Errorf("write output: %w", err)
		}
		return buf.Bytes(), nil
	}
	if err := writeReadinessPlan(&buf, report); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeReadinessPlan renders the default human-readable plan summary. Moved
// verbatim from cmd/apply/output.go:Reporter.ReportPlan (pure fmt.Fprintf —
// no cli/ui), minus the quiet gate which stays command-side.
func writeReadinessPlan(w io.Writer, report schemaval.ReadinessAssessment) error {
	if _, err := fmt.Fprintf(w, "Plan Summary\n------------\n"); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Ready:        %t\n", report.IsSafe); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Controls:     %s\n", report.ControlSource); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Checks: %s\n", report.ObservationSource); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Checked:      %d controls, %d snapshots, %d asset observations\n",
		report.Summary.ControlsVerified,
		report.Summary.StatesVerified,
		report.Summary.ResourcesAnalyzed); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	issues := report.Findings()
	if len(issues) > 0 {
		if _, err := fmt.Fprintln(w, "\nIssues:"); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		for _, issue := range issues {
			if err := printReadinessIssue(w, issue); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintf(w, "\nNext: %s\n", report.NextCommand()); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func printReadinessIssue(w io.Writer, issue schemaval.ValidationFinding) error {
	if _, err := fmt.Fprintf(w, "  [%s] %s: %s\n", issue.Status.String(), issue.Name, issue.Message); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if fix := strings.TrimSpace(issue.Remediation); fix != "" {
		if _, err := fmt.Fprintf(w, "    Fix: %s\n", fix); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
	if cmd := strings.TrimSpace(issue.FixCommand); cmd != "" {
		if _, err := fmt.Fprintf(w, "    Command: %s\n", cmd); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
	return nil
}
