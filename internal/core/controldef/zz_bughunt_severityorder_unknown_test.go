package controldef

import "testing"

// TestBugHunt_SeverityOrderUnknownRanksLeastSevere asserts the correct
// ordering contract for SeverityOrderOf: an unknown or empty severity
// string must NOT share Critical's rank.
//
// severityOrder maps Critical=0 (most severe) ... Info=4 (least severe),
// where a lower rank sorts as more severe. On an unrecognized or empty
// input, ParseSeverity errors and SeverityOrderOf returns
// severityOrder[SeverityNone]. SeverityNone is not a key in the map, so
// the lookup yields the zero value 0 — colliding with SeverityCritical.
// That makes garbage/empty severities sort as if they were the most
// severe level.
//
// Correct behavior: an unknown severity ranks as the LEAST severe, i.e.
// a value strictly greater than Info's rank (4), and must never equal
// Critical's rank (0).
func TestBugHunt_SeverityOrderUnknownRanksLeastSevere(t *testing.T) {
	criticalRank := SeverityOrderOf("critical")
	infoRank := SeverityOrderOf("info")

	// Sanity-check the known ordering assumption so the assertions below
	// are anchored to real ranks, not hard-coded magic numbers.
	if criticalRank >= infoRank {
		t.Fatalf("precondition failed: expected critical rank (%d) to be less (more severe) than info rank (%d)", criticalRank, infoRank)
	}

	for _, in := range []string{"garbage", "", "   ", "totally-not-a-severity"} {
		got := SeverityOrderOf(in)

		if got == criticalRank {
			t.Errorf("SeverityOrderOf(%q) = %d, which collides with Critical's rank (%d); unknown/empty severities sort as most severe", in, got, criticalRank)
		}

		if got <= infoRank {
			t.Errorf("SeverityOrderOf(%q) = %d; want strictly greater than Info's rank (%d) so unknown severities sort as LEAST severe", in, got, infoRank)
		}
	}
}
