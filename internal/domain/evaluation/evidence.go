package evaluation

import (
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
)

// RootCause represents the mechanism causing a violation (e.g., "policy", "acl").
type RootCause string

const (
	// RootCausePolicy indicates a bucket policy is the root cause.
	RootCausePolicy RootCause = "policy"
	// RootCauseACL indicates an ACL grant is the root cause.
	RootCauseACL RootCause = "acl"
)

// String implements fmt.Stringer.
func (rc RootCause) String() string {
	return string(rc)
}

// Evidence contains the proof of the violation.
// Fields are populated differently depending on the control type:
//   - Duration controls: FirstUnsafeAt, LastSeenUnsafeAt, UnsafeDurationHours, ThresholdHours
//   - Recurrence controls: EpisodeCount, WindowDays, RecurrenceLimit, FirstEpisodeAt, LastEpisodeAt
type Evidence struct {
	// FirstUnsafeAt is when the asset first entered the unsafe state (duration controls).
	FirstUnsafeAt time.Time `json:"first_unsafe_at,omitzero"`
	// LastSeenUnsafeAt is when the asset was last observed in an unsafe state.
	LastSeenUnsafeAt time.Time `json:"last_seen_unsafe_at,omitzero"`
	// UnsafeDurationHours is how long the asset has been continuously unsafe.
	UnsafeDurationHours float64 `json:"unsafe_duration_hours"`
	// ThresholdHours is the configured maximum allowed unsafe duration.
	ThresholdHours float64 `json:"threshold_hours"`

	// EpisodeCount is the number of unsafe episodes within the window (recurrence controls).
	EpisodeCount int `json:"episode_count,omitzero"`
	// WindowDays is the rolling window for counting recurrence (recurrence controls).
	WindowDays int `json:"window_days,omitzero"`
	// RecurrenceLimit is the maximum allowed episodes before violation (recurrence controls).
	RecurrenceLimit int `json:"recurrence_limit,omitzero"`
	// FirstEpisodeAt is when the first unsafe episode started (recurrence controls).
	FirstEpisodeAt time.Time `json:"first_episode_at,omitzero"`
	// LastEpisodeAt is when the most recent unsafe episode ended (recurrence controls).
	LastEpisodeAt time.Time `json:"last_episode_at,omitzero"`

	// Misconfigurations contains the specific property-level unsafe conditions
	// detected by the control's predicate. Sorted by Property lexicographically.
	Misconfigurations []policy.Misconfiguration `json:"misconfigurations,omitempty"`

	// RootCauses identifies the mechanism(s) causing the violation.
	// Values come from {"policy", "acl"}, derived from misconfiguration property paths.
	// Stable order: policy before acl.
	RootCauses []RootCause `json:"root_causes,omitempty"`

	// SourceEvidence contains pointers to the specific policy statements or ACL
	// entries that caused the violation. Only populated when vendor evidence is
	// available in the asset properties.
	SourceEvidence *SourceEvidence `json:"source_evidence,omitempty"`

	// WhyNow explains why this violation is being reported at this time.
	// Combines timing information with threshold context.
	WhyNow string `json:"why_now,omitempty"`
}

// RootCauseStrings returns root causes as string values in their existing order.
func (e Evidence) RootCauseStrings() []string {
	if len(e.RootCauses) == 0 {
		return nil
	}
	out := make([]string, len(e.RootCauses))
	for i := range e.RootCauses {
		out[i] = e.RootCauses[i].String()
	}
	return out
}

// SourceEvidence contains pointers to the specific policy statements or ACL
// entries that caused public exposure. Arrays are sorted lexicographically.
type SourceEvidence struct {
	// PolicyPublicStatements contains SIDs or numeric indices of policy statements
	// that grant public access.
	PolicyPublicStatements []string `json:"policy_public_statements,omitempty"`
	// ACLPublicGrantees contains grantee URIs (e.g., AllUsers, AuthenticatedUsers)
	// that grant public access.
	ACLPublicGrantees []string `json:"acl_public_grantees,omitempty"`
}

// DriftPattern classifies the temporal behavior of a violation.
type DriftPattern string

// Canonical drift pattern identifiers.
const (
	DriftPersistent   DriftPattern = "persistent"
	DriftDegraded     DriftPattern = "degraded"
	DriftIntermittent DriftPattern = "intermittent"
)

// PostureDrift classifies the temporal behavior of a violation.
// Computed from the asset.Timeline — not declared in control YAML.
type PostureDrift struct {
	// Pattern classifies the temporal behavior.
	// "persistent" — unsafe since first observation, never seen safe.
	// "degraded"   — was safe, now in first unsafe episode.
	// "intermittent" — has toggled between safe and unsafe at least once.
	Pattern DriftPattern `json:"pattern"`
	// EpisodeCount is the total number of unsafe episodes (closed + open).
	EpisodeCount int `json:"episode_count"`
}

// ComputePostureDrift derives posture drift from an asset.Timeline.
// Returns nil when the asset is not currently unsafe.
func ComputePostureDrift(timeline *asset.Timeline) *PostureDrift {
	if timeline.CurrentlySafe() {
		return nil
	}

	closedEpisodes := timeline.History().Count()
	totalEpisodes := closedEpisodes + 1 // +1 for the open episode

	var pattern DriftPattern
	switch {
	case closedEpisodes > 0:
		pattern = DriftIntermittent
	case timeline.HasOpenEpisode() && timeline.Stats().HasFirstObservation() &&
		timeline.FirstUnsafeAt().After(timeline.Stats().FirstSeenAt()):
		pattern = DriftDegraded
	default:
		pattern = DriftPersistent
	}

	return &PostureDrift{
		Pattern:      pattern,
		EpisodeCount: totalEpisodes,
	}
}
