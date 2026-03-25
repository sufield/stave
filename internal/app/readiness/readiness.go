package readiness

import (
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/diag"
	"github.com/sufield/stave/pkg/alpha/domain/validation"
)

func AssessReadiness(in validation.Input) (validation.Report, error) {
	report := validation.NewReport(in.ControlsDir, in.ObservationsDir)
	recordPrereqIssues(report, in.PrereqChecks)
	recordControlSourceIssue(report, in)
	if err := recordValidationIssues(readinessValidationRequest{
		Report:            report,
		Input:             in,
		MaxUnsafeDuration: in.MaxUnsafeDuration,
		Now:               in.Now,
	}); err != nil {
		return validation.Report{}, err
	}
	return *report, nil
}

func recordPrereqIssues(report *validation.Report, checks []validation.Issue) {
	for _, check := range checks {
		if check.Status == validation.StatusPass {
			continue
		}
		report.RecordIssue(check)
	}
}

func recordControlSourceIssue(report *validation.Report, in validation.Input) {
	if !in.HasEnabledControlPacks || !in.ControlsFlagSet {
		return
	}
	report.RecordIssue(validation.Issue{
		Name:    "control-source-selection",
		Status:  validation.StatusFail,
		Message: "cannot combine explicit --controls with enabled_control_packs",
		Fix:     "remove --controls or clear enabled_control_packs in stave.yaml",
		Command: "stave status",
	})
}

type readinessValidationRequest struct {
	Report            *validation.Report
	Input             validation.Input
	MaxUnsafeDuration time.Duration
	Now               time.Time
}

func recordValidationIssues(req readinessValidationRequest) error {
	if req.Input.Validate == nil || req.Report == nil {
		return nil
	}

	val, err := req.Input.Validate(req.MaxUnsafeDuration, req.Now)
	if err != nil {
		return err
	}
	req.Report.Summary.ControlsChecked = val.Summary.ControlsLoaded
	req.Report.Summary.SnapshotsChecked = val.Summary.SnapshotsLoaded
	req.Report.Summary.AssetObservationsChecked = val.Summary.AssetObservationsLoaded

	for _, issue := range readinessDiagnostics(val).Issues {
		req.Report.RecordIssue(validation.Issue{
			Name:    string(issue.Code),
			Status:  readinessIssueStatus(issue),
			Message: issue.Action,
			Fix:     issue.Action,
			Command: issue.Command,
		})
	}
	return nil
}

func readinessDiagnostics(val validation.Result) *diag.Result {
	if val.Diagnostics != nil {
		return val.Diagnostics
	}
	return diag.NewResult()
}

func readinessIssueStatus(issue diag.Issue) validation.Status {
	if issue.Signal == diag.SignalError {
		return validation.StatusFail
	}
	return validation.StatusWarn
}
