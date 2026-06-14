package sirfacts

import (
	"testing"

	"github.com/sufield/stave/internal/core/sir"
)

// TestBugHunt_ExposureFactsHonorDurationUnreliable proves the fact projection
// surfaces the SIR's DurationUnreliable signal to the reasoning layer.
//
// The SIR builder flags clamped / zero-dwell exposure windows with
// DurationUnreliable=true so downstream consumers decline to grade SLA breach
// from an untrustworthy duration. But the reasoning bridge — exposureFacts —
// emitted has_exposure_window=true identically for reliable and clamped
// windows and dropped the flag entirely, so the Datalog/SMT corpus could not
// distinguish them: the flag was dead at the bridge, and any future dwell
// query would treat a clamped window as a trustworthy exposure.
//
// Correct behavior: a window carrying DurationUnreliable emits a companion
// has_unreliable_exposure_duration triple (the existence fact
// has_exposure_window is still emitted — the exposure did occur — only the
// dwell is flagged untrustworthy). A reliable window emits no such triple.
func TestBugHunt_ExposureFactsHonorDurationUnreliable(t *testing.T) {
	t.Parallel()

	windows := []sir.ExposureWindow{
		{
			AssetID:                "arn:aws:s3:::bucket-reliable",
			UnsafePredicateMatched: true,
			ContributingControls:   []string{"CTL.S3.PUBLIC.001"},
		},
		{
			AssetID:                "arn:aws:s3:::bucket-clamped",
			UnsafePredicateMatched: true,
			DurationUnreliable:     true,
			ContributingControls:   []string{"CTL.S3.PUBLIC.001"},
		},
	}

	facts := exposureFacts(windows)

	has := func(subject, predicate string) bool {
		for i := range facts {
			f := &facts[i]
			if f.Subject == subject && f.Predicate == predicate && f.Object == "true" {
				return true
			}
		}
		return false
	}

	// The existence fact is emitted for both windows.
	if !has("arn:aws:s3:::bucket-reliable", "has_exposure_window") {
		t.Errorf("reliable window missing has_exposure_window")
	}
	if !has("arn:aws:s3:::bucket-clamped", "has_exposure_window") {
		t.Errorf("clamped window missing has_exposure_window (the exposure still occurred)")
	}

	// Only the clamped window carries the unreliable-duration signal.
	if has("arn:aws:s3:::bucket-reliable", "has_unreliable_exposure_duration") {
		t.Errorf("reliable window must NOT emit has_unreliable_exposure_duration")
	}
	if !has("arn:aws:s3:::bucket-clamped", "has_unreliable_exposure_duration") {
		t.Errorf("DurationUnreliable window must emit has_unreliable_exposure_duration so " +
			"the reasoning layer can decline to grade dwell from it")
	}
}
