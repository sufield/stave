package service

import (
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/diag"
	"github.com/sufield/stave/pkg/alpha/domain/validation"
)

func AssessReadiness(in validation.ReadinessInput) (validation.ReadinessReport, error) {
	report := validation.NewReadinessReport(in.ControlsDir, in.ObservationsDir)
	recordPrereqIssues(report, in.PrereqChecks)
	recordControlSourceIssue(report, in)
	if err := recordValidationIssues(readinessValidationRequest{
		Report:            report,
		Input:             in,
		MaxUnsafeDuration: in.MaxUnsafeDuration,
		Now:               in.Now,
	}); err != nil {
		return validation.ReadinessReport{}, err
	}
	report.Finalize()
	return *report, nil
}

func recordPrereqIssues(report *validation.ReadinessReport, checks []validation.PrereqCheck) {
	for _, check := range checks {
		if check.Status == validation.StatusPass {
			continue
		}
		report.RecordIssue(validation.Issue{
			Name:    check.Name,
			Status:  check.Status,
			Message: check.Message,
			Fix:     check.Fix,
		})
	}
}

func recordControlSourceIssue(report *validation.ReadinessReport, in validation.ReadinessInput) {
	if !in.HasEnabledControlPack || !in.ControlsFlagSet {
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
	Report            *validation.ReadinessReport
	Input             validation.ReadinessInput
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
