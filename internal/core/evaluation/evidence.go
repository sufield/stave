package evaluation

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// RootCause represents the high-level mechanism causing a violation.
type RootCause string

const (
	// RootCauseIdentity indicates an identity-bound policy (e.g., IAM, RBAC) is the cause.
	RootCauseIdentity RootCause = "identity"
	// RootCauseResource indicates a resource-bound policy (e.g., Bucket Policy, ACL) is the cause.
	RootCauseResource RootCause = "resource"
	// RootCauseGeneral indicates misconfigurations exist but none are categorized.
	RootCauseGeneral RootCause = "general"
)

func (rc RootCause) String() string {
	return string(rc)
}

// Evidence contains the audit-ready proof of a violation.
//
// Fields are conditionally populated based on the control type:
//   - Duration: FirstUnsafeAt, LastSeenUnsafeAt, UnsafeDurationHours, ThresholdHours
//   - Recurrence: ExposureWindowCount, WindowDays, RecurrenceLimit, FirstExposureWindowAt, LastExposureWindowAt
type Evidence struct {
	// --- Duration Timing ---
	FirstUnsafeAt       time.Time `json:"first_unsafe_at,omitzero"`
	LastSeenUnsafeAt    time.Time `json:"last_seen_unsafe_at,omitzero"`
	UnsafeDurationHours float64   `json:"unsafe_duration_hours,omitempty"`
	ThresholdHours      float64   `json:"threshold_hours,omitempty"`

	// --- Recurrence Frequency ---
	ExposureWindowCount   int       `json:"exposure_window_count,omitempty"`
	WindowDays            int       `json:"window_days,omitempty"`
	RecurrenceLimit       int       `json:"recurrence_limit,omitempty"`
	FirstExposureWindowAt time.Time `json:"first_exposure_window_at,omitzero"`
	LastExposureWindowAt  time.Time `json:"last_exposure_window_at,omitzero"`

	// --- Logical Evidence ---
	Misconfigurations []policy.Misconfiguration `json:"misconfigurations,omitempty"`
	RootCauses        []RootCause               `json:"root_causes,omitempty"`
	SourceEvidence    *SourceEvidence           `json:"source_evidence,omitempty"`

	// TemporalRisk is a human-readable summary of the current violation state.
	TemporalRisk string `json:"temporal_risk,omitempty"`

	// EvidenceInvalid is set when the strategy could not produce a
	// faithful Evidence record but emitted a finding anyway —
	// typically because duration math failed and the strategy
	// fell back to a sentinel duration of -1.0. Consumers that
	// surface evidence in reports should treat the row as
	// "violation confirmed, evidence unreliable" and avoid
	// performing arithmetic on UnsafeDurationHours when this is
	// true. The earlier shape only logged the underlying error,
	// so downstream rendering had no way to distinguish a real
	// duration from the sentinel.
	EvidenceInvalid bool `json:"evidence_invalid,omitempty"`
}

// RootCauseStrings converts typed causes to a raw string slice.
func (e Evidence) RootCauseStrings() []string {
	if len(e.RootCauses) == 0 {
		return nil
	}
	out := make([]string, len(e.RootCauses))
	for i, rc := range e.RootCauses {
		out[i] = string(rc)
	}
	return out
}

// SourceEvidence provides pointers to specific configuration entries (e.g. SIDs, Grantees).
type SourceEvidence struct {
	// IdentityStatements lists IDs/indices of identity-bound policies (e.g., IAM SIDs).
	IdentityStatements []kernel.StatementID `json:"identity_statements,omitempty"`
	// ResourceGrantees lists specific entities granted access via resource-bound policies (e.g., ACL URIs).
	ResourceGrantees []kernel.GranteeID `json:"resource_grantees,omitempty"`
}

// DriftPattern classifies the temporal behavior of a violation.
type DriftPattern string

const (
	// DriftPersistent indicates the asset has been unsafe since the very first observation.
	DriftPersistent DriftPattern = "persistent"
	// DriftDegraded indicates the asset was safe initially but has since entered an unsafe state.
	DriftDegraded DriftPattern = "degraded"
	// DriftIntermittent indicates the asset has toggled between safe and unsafe multiple times.
	DriftIntermittent DriftPattern = "intermittent"
)

// PostureDrift describes how a violation has evolved over time.
type PostureDrift struct {
	Pattern             DriftPattern `json:"pattern"`
	ExposureWindowCount int          `json:"exposure_window_count"`
}

// ComputePostureDrift analyzes a lifecycle to classify the violation's drift pattern.
// Returns nil if the asset is not currently in an unsafe state.
func ComputePostureDrift(t *asset.ExposureLifecycle) *PostureDrift {
	if t.IsSecure() {
		return nil
	}

	history := t.History()
	closedCount := history.Count()
	totalEpisodes := closedCount + 1 // Existing history + current open exposure window

	var pattern DriftPattern
	switch {
	case closedCount > 0:
		// If there are any closed exposure windows in history, it means the asset was
		// previously unsafe, then safe, and is now unsafe again.
		pattern = DriftIntermittent

	case t.HasActiveWindow() && t.Stats().HasFirstObservation():
		// Check if the asset was safe at the start of its known history.
		if t.FirstExposedAt().After(t.Stats().FirstSeenAt()) {
			pattern = DriftDegraded
		} else {
			pattern = DriftPersistent
		}

	default:
		pattern = DriftPersistent
	}

	return &PostureDrift{
		Pattern:             pattern,
		ExposureWindowCount: totalEpisodes,
	}
}
