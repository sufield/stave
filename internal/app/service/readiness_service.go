package service

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/domain/validation"
	"github.com/sufield/stave/internal/pkg/timeutil"
)

var (
	ErrInvalidMaxUnsafe = errors.New("invalid max-unsafe")
	ErrInvalidNow       = errors.New("invalid now")
)

func AssessReadiness(in validation.ReadinessInput) (validation.ReadinessReport, error) {
	maxDur, now, err := parseReadinessInputs(in.MaxUnsafe, in.Now)
	if err != nil {
		return validation.ReadinessReport{}, err
	}

	report := validation.ReadinessReport{
		Ready:           true,
		ControlsDir:     in.ControlsDir,
		ObservationsDir: in.ObservationsDir,
	}
	recordPrereqIssues(&report, in.PrereqChecks)
	recordControlSourceIssue(&report, in)
	if err := recordValidationIssues(readinessValidationRequest{
		Report:    &report,
		Input:     in,
		MaxUnsafe: maxDur,
		Now:       now,
	}); err != nil {
		return validation.ReadinessReport{}, err
	}
	report.Finalize()
	return report, nil
}

func recordPrereqIssues(report *validation.ReadinessReport, checks []validation.PrereqCheck) {
	for _, check := range checks {
		if check.Status == validation.PrereqPass {
			continue
		}
		report.RecordIssue(validation.ReadinessIssue{
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
	report.RecordIssue(validation.ReadinessIssue{
		Name:    "control-source-selection",
		Status:  validation.PrereqFail,
		Message: "cannot combine explicit --controls with enabled_control_packs",
		Fix:     "remove --controls or clear enabled_control_packs in stave.yaml",
		Command: "stave status",
	})
}

type readinessValidationRequest struct {
	Report    *validation.ReadinessReport
	Input     validation.ReadinessInput
	MaxUnsafe time.Duration
	Now       time.Time
}

func recordValidationIssues(req readinessValidationRequest) error {
	if req.Input.Validate == nil || req.Report == nil {
		return nil
	}

	val, err := req.Input.Validate(req.MaxUnsafe, req.Now)
	if err != nil {
		return err
	}
	req.Report.Summary.ControlsChecked = val.Summary.ControlsLoaded
	req.Report.Summary.SnapshotsChecked = val.Summary.SnapshotsLoaded
	req.Report.Summary.AssetObservationsChecked = val.Summary.AssetObservationsLoaded

	for _, issue := range readinessDiagnostics(val).Issues {
		req.Report.RecordIssue(validation.ReadinessIssue{
			Name:    issue.Code,
			Status:  readinessIssueStatus(issue),
			Message: issue.Action,
			Fix:     issue.Action,
			Command: issue.Command,
		})
	}
	return nil
}

func readinessDiagnostics(val validation.ReadinessValidationResult) *diag.Result {
	if val.Diagnostics != nil {
		return val.Diagnostics
	}
	return diag.NewResult()
}

func readinessIssueStatus(issue diag.Issue) validation.PrereqStatus {
	if issue.Signal == diag.SignalError {
		return validation.PrereqFail
	}
	return validation.PrereqWarn
}

func parseReadinessInputs(maxUnsafeStr, nowStr string) (time.Duration, time.Time, error) {
	dur, err := timeutil.ParseDurationFlag(strings.TrimSpace(maxUnsafeStr), "max-unsafe")
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("%w: %s", ErrInvalidMaxUnsafe, err)
	}

	nowStr = strings.TrimSpace(nowStr)
	if nowStr == "" {
		return dur, time.Time{}, nil
	}

	now, err := timeutil.ParseRFC3339(nowStr, "--now")
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("%w: %v", ErrInvalidNow, err)
	}

	return dur, now, nil
}
