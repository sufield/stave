package kernel

import (
	"encoding/json"
	"testing"
	"time"
)

// TestBugHunt_DurationLargeValueJSONRoundTrips proves that a Duration with a
// large (but valid) magnitude survives a JSON marshal → unmarshal round trip.
//
// FormatDuration formatted the hour count with fmt.Sprintf("%gh", h). For
// h >= 1e6 (≈114 years — well within time.Duration's ~292-year range), %g
// switches to scientific notation, e.g. "2e+06h". MarshalJSON emits that
// string, but UnmarshalJSON → ParseDuration → time.ParseDuration rejects it
// ("unknown unit \"e+\""), so a value the type can represent and serialize
// cannot be read back. That breaks the Duration serialization contract
// (MarshalJSON/UnmarshalJSON must round-trip) for any sufficiently large
// duration.
//
// Correct behavior: FormatDuration emits a plain-decimal, parseable string.
func TestBugHunt_DurationLargeValueJSONRoundTrips(t *testing.T) {
	orig := Duration(2_000_000 * time.Hour) // ~228 years — a valid time.Duration

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var back Duration
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("round-trip broken: marshaled as %s but UnmarshalJSON failed: %v "+
			"(FormatDuration emitted unparseable scientific notation)", data, err)
	}
	if back != orig {
		t.Errorf("round-trip mismatch: got %v, want %v", back.Std(), orig.Std())
	}
}

// TestBugHunt_ParseLargeDayValue proves that ParseDuration handles a large
// day value. normalizeDaysToHours converted "Nd" to hours with
// fmt.Sprintf("%gh", days*24); for N*24 >= 1e6 that produced scientific
// notation (e.g. "1.2e+06h") which time.ParseDuration then rejected, so a
// representable duration expressed in days failed to parse.
//
// Correct behavior: the day value parses to its hour equivalent.
func TestBugHunt_ParseLargeDayValue(t *testing.T) {
	got, err := ParseDuration("50000d") // 50000*24 = 1.2e6 hours — valid, but triggered %g
	if err != nil {
		t.Fatalf(`ParseDuration("50000d") failed: %v `+
			`(normalizeDaysToHours emitted unparseable scientific notation)`, err)
	}
	want := 50000 * 24 * time.Hour
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}
