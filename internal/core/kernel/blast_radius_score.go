package kernel

import "encoding/json"

// BlastRadius quantifies how widely a single finding's failure can
// propagate — how many other principals, accounts, or resources are
// affected if the unsafe state is exploited. The numeric value is
// the underlying multiplier / count; the type adds semantic
// accessors (IsSignificant) so call sites don't open-code the
// "what counts as significant?" cliff.
//
// Distinct from BlastRadiusType / BlastScope (in blast_radius.go),
// which classify the *category* of blast and are control-authoring
// inputs. BlastRadius is the scalar produced by the runtime
// reachability calculation.
//
// Zero value semantics: BlastRadius(0) is "not computed" /
// "negligible blast", matching the existing convention. Use
// IsSignificant() to gate on a meaningful blast threshold rather
// than open-coding `score > 1.0` at every call site.
//
// Comparison: as with ExposureScore, two BlastRadius values can no
// longer be silently mixed with raw floats from other domains —
// callers go through Value() or wrap a literal.
type BlastRadius float64

// blastRadiusSignificantMin is the cutoff above which a blast
// radius counts as "significant" for the IsSignificant predicate.
// 1.0 is the neutral / single-resource baseline; anything above
// that means at least one additional account / principal /
// resource is affected.
const blastRadiusSignificantMin = 1.0

// NewBlastRadius returns a BlastRadius. No bounds enforcement —
// values legitimately exceed any fixed cap when an asset is
// reachable from many accounts.
func NewBlastRadius(v float64) BlastRadius {
	return BlastRadius(v)
}

// Value returns the underlying float64.
func (b BlastRadius) Value() float64 { return float64(b) }

// IsEmpty reports whether the blast radius is the zero value
// (i.e. unset / not computed).
func (b BlastRadius) IsEmpty() bool { return b == 0 }

// IsSignificant reports whether the blast radius exceeds the
// configured significance threshold. The threshold sits in this
// file so a future adjustment is a single-line change rather than
// a sweep through every consumer.
func (b BlastRadius) IsSignificant() bool { return float64(b) > blastRadiusSignificantMin }

// MarshalJSON preserves the numeric wire form.
func (b BlastRadius) MarshalJSON() ([]byte, error) {
	return json.Marshal(float64(b))
}

// UnmarshalJSON parses a JSON number.
func (b *BlastRadius) UnmarshalJSON(data []byte) error {
	var v float64
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*b = BlastRadius(v)
	return nil
}
