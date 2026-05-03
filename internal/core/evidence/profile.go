package evidence

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ThresholdMode defines how pass/fail is determined for a requirement.
type ThresholdMode int

const (
	ThresholdAll     ThresholdMode = iota // Every mapped control must pass
	ThresholdAny                          // At least one mapped control must pass
	ThresholdPercent                      // >=N% of mapped controls must pass
)

// String returns the wire-format name of the threshold mode.
func (m ThresholdMode) String() string {
	switch m {
	case ThresholdAll:
		return "all"
	case ThresholdAny:
		return "any"
	case ThresholdPercent:
		return "percent"
	default:
		return "unknown"
	}
}

// PassThreshold defines how many controls must pass for a requirement to be met.
type PassThreshold struct {
	Mode    ThresholdMode
	Percent float64 // only used when Mode == ThresholdPercent
}

// Sentinel errors for ParsePassThreshold so callers can errors.Is
// against specific failure modes (range vs unknown form).
var (
	ErrThresholdOutOfRange = errors.New("evidence: percent threshold out of [0,100] range")
	ErrThresholdUnknown    = errors.New("evidence: unknown threshold form (expected all, any, or percent:N)")
)

// ParsePassThreshold parses a threshold string: "all", "any", or "percent:N".
func ParsePassThreshold(s string) (PassThreshold, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "" || s == "all":
		return PassThreshold{Mode: ThresholdAll}, nil
	case s == "any":
		return PassThreshold{Mode: ThresholdAny}, nil
	case strings.HasPrefix(s, "percent:"):
		pct, err := strconv.ParseFloat(strings.TrimPrefix(s, "percent:"), 64)
		if err != nil {
			return PassThreshold{}, fmt.Errorf("invalid percent threshold %q: %w", s, err)
		}
		if pct < 0 || pct > 100 {
			return PassThreshold{}, fmt.Errorf("%w: got %v", ErrThresholdOutOfRange, pct)
		}
		return PassThreshold{Mode: ThresholdPercent, Percent: pct}, nil
	default:
		return PassThreshold{}, fmt.Errorf("%w: %q", ErrThresholdUnknown, s)
	}
}

// Requirement is a single regulatory requirement within a framework profile.
type Requirement struct {
	ID            string
	Description   string
	Section       string
	ControlIDs    []string
	PassThreshold PassThreshold
}

// FrameworkProfile defines the compliance profile for a regulatory framework.
type FrameworkProfile struct {
	ID           string
	Name         string
	Version      string
	Description  string
	FrameworkKey string // matches controldef.ComplianceFramework key
	Requirements []Requirement
}

// RequirementStatus is the outcome of evaluating a single regulatory requirement.
type RequirementStatus int

const (
	RequirementMet          RequirementStatus = iota // All thresholds satisfied
	RequirementNotMet                                // Threshold not reached
	RequirementNotEvaluated                          // No evidence records for any control
	RequirementIncomplete                            // Evidence exists but contains incomplete verdicts
)

// String returns the wire-format name of the requirement status.
func (s RequirementStatus) String() string {
	switch s {
	case RequirementMet:
		return "met"
	case RequirementNotMet:
		return "not_met"
	case RequirementNotEvaluated:
		return "not_evaluated"
	case RequirementIncomplete:
		return "incomplete"
	default:
		return "unknown"
	}
}

// RequirementAssessment is the evaluation result for a single requirement.
type RequirementAssessment struct {
	RequirementID     string
	Description       string
	Section           string
	Status            RequirementStatus
	PassCount         int
	FailCount         int
	IncompleteCount   int
	TotalControls     int     // len(Requirement.ControlIDs)
	EvaluatedControls int     // controls with at least one evidence record
	CoveragePercent   float64 // PassCount / max(EvaluatedControls, 1) * 100
	Evidence          []*EvidenceRecord
}

// IsMet reports whether the requirement evaluated as fully
// satisfied. Centralises the Status comparison so callers stop
// reading the raw enum.
func (r *RequirementAssessment) IsMet() bool {
	return r != nil && r.Status == RequirementMet
}

// IsNotEvaluated reports whether the requirement could not be
// evaluated (no evidence collected, framework gaps).
func (r *RequirementAssessment) IsNotEvaluated() bool {
	return r != nil && r.Status == RequirementNotEvaluated
}

// IsActionable reports whether this requirement assessment carries a
// status the gap-collection pass should fold into the cross-framework
// gap map. Met (everything satisfied) and NotEvaluated (no evidence
// at all) both contribute zero gaps and are skipped; NotMet and
// Incomplete are actionable. Routes through IsMet / IsNotEvaluated
// so a future status addition lands one place.
func (r *RequirementAssessment) IsActionable() bool {
	if r == nil {
		return false
	}
	return !r.IsMet() && !r.IsNotEvaluated()
}

// OscalState returns the (state, reason) pair the OSCAL exporter
// emits for this requirement. Centralises the
// (RequirementStatus → OSCAL state/reason) mapping so the renderer
// stops switching on Status. The default state is "satisfied" with
// no reason; non-Met statuses translate to "not-satisfied" with a
// reason word that matches the OSCAL implementation-status.reason
// vocabulary.
func (r *RequirementAssessment) OscalState() (state, reason string) {
	if r == nil {
		return "satisfied", ""
	}
	switch r.Status {
	case RequirementNotMet:
		return "not-satisfied", "fail"
	case RequirementIncomplete:
		return "not-satisfied", "incomplete"
	case RequirementNotEvaluated:
		return "not-satisfied", "not-evaluated"
	default:
		return "satisfied", ""
	}
}

// ProfileAssessment is the complete result of evaluating a framework profile
// against an EvidencePackage.
type ProfileAssessment struct {
	FrameworkID       string
	FrameworkName     string
	FrameworkVersion  string
	Requirements      []RequirementAssessment
	MetCount          int
	NotMetCount       int
	NotEvaluatedCount int
	IncompleteCount   int
	TotalRequirements int
	CoveragePercent   float64 // MetCount / TotalRequirements * 100
}
