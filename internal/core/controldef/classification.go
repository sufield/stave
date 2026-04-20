package controldef

// Classification expresses a control's semantic evaluation role,
// distinct from Type (engine-level mechanism — unsafe_state,
// unsafe_recurrence, etc.) and Domain (asset class).
//
// The classification lets downstream consumers filter findings by
// what the control actually checks. A consumer asking "is this
// asset in the unsafe state?" filters by ClassificationStateAssertion;
// findings from absence checks (which fire on missing evidence,
// not on observed unsafe state) and parameterized checks (which
// compare against thresholds) are excluded. Without this primitive,
// every consumer rebuilds the distinction via control_id substring
// heuristics — see docs/audits/2026-04-internal-verification.md
// resolution log for the bucket-intent prototype's false-positive
// case that motivated adding the field.
type Classification string

const (
	// ClassificationStateAssertion: control fires when an
	// observable asset state matches an unsafe value. The most
	// common shape; e.g., `block_public_acls eq false` fires
	// because the flag is actively the unsafe value.
	ClassificationStateAssertion Classification = "state_assertion"

	// ClassificationParameterizedCheck: control fires when an
	// asset's state is unsafe relative to a parameterized
	// threshold or value. e.g., `unused_days gt 45`,
	// `password_minimum_length lt 14`, controls using
	// `value_from_param` or `any_in_field` against control
	// parameters.
	ClassificationParameterizedCheck Classification = "parameterized_check"

	// ClassificationAbsenceCheck: control fires when required
	// evidence is missing. e.g., `op: missing` predicates,
	// `prefix_exposure` controls firing on missing-evidence
	// signals. Distinct from state_assertion because the asset
	// is not in an observed unsafe state — the evidence required
	// to evaluate it is absent.
	ClassificationAbsenceCheck Classification = "absence_check"

	// ClassificationAggregateCheck: control fires when a computed
	// aggregate across multiple observations matches an unsafe
	// condition. Includes time-based aggregates
	// (unsafe_duration, unsafe_recurrence) and umbrella controls
	// that require multiple flags to be in unsafe states.
	ClassificationAggregateCheck Classification = "aggregate_check"
)

// String returns the underlying string for use in templates and logs.
func (c Classification) String() string { return string(c) }

// IsValid reports whether c is one of the four known
// classifications. The schema validator enforces this at load
// time; the helper exists for defensive checks elsewhere.
func (c Classification) IsValid() bool {
	switch c {
	case ClassificationStateAssertion,
		ClassificationParameterizedCheck,
		ClassificationAbsenceCheck,
		ClassificationAggregateCheck:
		return true
	}
	return false
}
