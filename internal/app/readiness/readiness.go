package readiness

import (
	"time"

	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/outcome"
	validation "github.com/sufield/stave/internal/core/schemaval"
)

// AssessReadiness runs prerequisite, control-source, and validation checks
// and returns a readiness report summarizing any issues found.
func AssessReadiness(in validation.AssessmentContext) (validation.ReadinessAssessment, error) {
	report := validation.NewReadinessAssessment(in.ControlSource, in.ObservationSource)
	recordPrereqIssues(report, in.PreflightChecks)
	recordControlSourceIssue(report, in)
	if err := recordValidationIssues(readinessValidationRequest{
		Report:            report,
		Input:             in,
		MaxUnsafeDuration: in.SLAThreshold,
		Now:               in.CurrentTime,
	}); err != nil {
		return validation.ReadinessAssessment{}, err
	}
	return *report, nil
}

func recordPrereqIssues(report *validation.ReadinessAssessment, checks []validation.ValidationFinding) {
	for i := range checks {
		if checks[i].IsPassing() {
			continue
		}
		report.RecordFinding(checks[i])
	}
}

func recordControlSourceIssue(report *validation.ReadinessAssessment, in validation.AssessmentContext) {
	if !in.HasEnabledControlPacks || !in.ControlFlagsSet {
		return
	}
	// Explicit --controls flag overrides enabled_control_packs.
	// This is not a conflict — the CLI flag takes precedence.
	report.RecordFinding(validation.ValidationFinding{
		Name:        "control-source-selection",
		Status:      outcome.Pass,
		Message:     "--controls flag overrides enabled_control_packs from stave.yaml",
		Remediation: "",
	})
}

type readinessValidationRequest struct {
	Report            *validation.ReadinessAssessment
	Input             validation.AssessmentContext
	MaxUnsafeDuration time.Duration
	Now               time.Time
}

func recordValidationIssues(req readinessValidationRequest) error {
	if req.Input.RunEvaluation == nil || req.Report == nil {
		return nil
	}

	val, err := req.Input.RunEvaluation(req.MaxUnsafeDuration, req.Now)
	if err != nil {
		return err
	}
	req.Report.Summary.ControlsVerified = val.LoadMetrics.ControlsLoaded
	req.Report.Summary.StatesVerified = val.LoadMetrics.SnapshotsLoaded
	req.Report.Summary.ResourcesAnalyzed = val.LoadMetrics.ResourcesLoaded

	for _, issue := range readinessDiagnostics(val).Findings {
		req.Report.RecordFinding(validation.ValidationFinding{
			Name:        string(issue.RuleID),
			Status:      readinessIssueStatus(issue),
			Message:     issue.Remediation,
			Remediation: issue.Remediation,
			FixCommand:  issue.FixCommand,
		})
	}
	return nil
}

func readinessDiagnostics(val validation.EvaluationState) *diag.Assessment {
	if val.Diagnostics != nil {
		return val.Diagnostics
	}
	return diag.NewAssessment()
}

func readinessIssueStatus(issue diag.Finding) outcome.Status {
	if issue.Severity == diag.SeverityError {
		return outcome.Fail
	}
	return outcome.Warn
}
