package evaluation

import (
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
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
//   - Recurrence: EpisodeCount, WindowDays, RecurrenceLimit, FirstEpisodeAt, LastEpisodeAt
type Evidence struct {
	// --- Duration Timing ---
	FirstUnsafeAt       time.Time `json:"first_unsafe_at,omitzero"`
	LastSeenUnsafeAt    time.Time `json:"last_seen_unsafe_at,omitzero"`
	UnsafeDurationHours float64   `json:"unsafe_duration_hours,omitempty"`
	ThresholdHours      float64   `json:"threshold_hours,omitempty"`

	// --- Recurrence Frequency ---
	EpisodeCount    int       `json:"episode_count,omitempty"`
	WindowDays      int       `json:"window_days,omitempty"`
	RecurrenceLimit int       `json:"recurrence_limit,omitempty"`
	FirstEpisodeAt  time.Time `json:"first_episode_at,omitzero"`
	LastEpisodeAt   time.Time `json:"last_episode_at,omitzero"`

	// --- Logical Evidence ---
	Misconfigurations []policy.Misconfiguration `json:"misconfigurations,omitempty"`
	RootCauses        []RootCause               `json:"root_causes,omitempty"`
	SourceEvidence    *SourceEvidence           `json:"source_evidence,omitempty"`

	// WhyNow is a human-readable summary of the current violation state.
	WhyNow string `json:"why_now,omitempty"`
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
	// DriftPersistent: Asset has been unsafe since the very first observation.
	DriftPersistent DriftPattern = "persistent"
	// DriftDegraded: Asset was safe initially but has since entered an unsafe state.
	DriftDegraded DriftPattern = "degraded"
	// DriftIntermittent: Asset has toggled between safe and unsafe multiple times.
	DriftIntermittent DriftPattern = "intermittent"
)

// PostureDrift describes how a violation has evolved over time.
type PostureDrift struct {
	Pattern      DriftPattern `json:"pattern"`
	EpisodeCount int          `json:"episode_count"`
}

// ComputePostureDrift analyzes a timeline to classify the violation's drift pattern.
// Returns nil if the asset is not currently in an unsafe state.
func ComputePostureDrift(t *asset.Timeline) *PostureDrift {
	if t.CurrentlySafe() {
		return nil
	}

	history := t.History()
	closedCount := history.Count()
	totalEpisodes := closedCount + 1 // Existing history + current open episode

	var pattern DriftPattern
	switch {
	case closedCount > 0:
		// If there are any closed episodes in history, it means the asset was
		// previously unsafe, then safe, and is now unsafe again.
		pattern = DriftIntermittent

	case t.HasOpenEpisode() && t.Stats().HasFirstObservation():
		// Check if the asset was safe at the start of its known history.
		if t.FirstUnsafeAt().After(t.Stats().FirstSeenAt()) {
			pattern = DriftDegraded
		} else {
			pattern = DriftPersistent
		}

	default:
		pattern = DriftPersistent
	}

	return &PostureDrift{
		Pattern:      pattern,
		EpisodeCount: totalEpisodes,
	}
}
