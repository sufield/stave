package cel

import (
	"strings"
	"testing"
)

// The Bug-5 capacity guard rejects a declared entry count that exceeds what the
// remaining buffer can physically hold, BEFORE the slice is pre-sized and BEFORE
// the per-entry read loop runs. Its contract is twofold:
//  1. it fires at the guard (not later, in the truncation path), and
//  2. it computes the threshold as remaining/40 — 40 being the minimum bytes a
//     real entry occupies (32-byte SHA + two 4-byte length prefixes).
//
// A count of 1 over a 32-byte trailing buffer (a bare SHA, no length prefixes)
// sits in the gap that only the real 40-byte minimum rejects:
//   - real:        1 >  32/40 (=0)  -> true  -> rejected at the guard.
//   - any mutation that loosens the guard (minEntryBytes 40->32 via the
//     `32 + 4 + 4` arithmetic; `remaining/40` -> `remaining*40`;
//     `len(buf) - pos` -> `len(buf) + pos`; or inverting pos) makes the
//     threshold >= 1, so 1 is NOT rejected at the guard. Such a mutant slips
//     past the guard into the read loop, reads the bare SHA, then fails on the
//     MISSING expression length prefix with a *different* diagnostic
//     ("truncated expression at entry 0").
//
// Asserting the specific capacity-guard message therefore distinguishes the real
// pre-check from every loosened variant: an err==nil check would miss them (both
// paths error), but only the real guard reports the buffer-capacity overflow.
func TestDecodeCache_OverCapacityCount_RejectedAtGuardNotInLoop(t *testing.T) {
	// count == 1, but only a bare 32-byte SHA follows (32 trailing bytes).
	// 32 < 40, so one entry cannot fit: the capacity guard must reject it.
	data := buildHeaderWithCount(1)
	var sha [32]byte
	data = append(data, sha[:]...)

	_, err := decodeCache(data)
	if err == nil {
		t.Fatal("decodeCache accepted count=1 over a 32-byte buffer; the capacity guard must reject it")
	}
	// The capacity guard's message — not the in-loop truncation message — proves
	// the over-capacity count was rejected up front, before any per-entry read.
	if !strings.Contains(err.Error(), "exceeds") || !strings.Contains(err.Error(), "buffer capacity") {
		t.Fatalf("want the capacity-guard rejection (remaining/40 threshold), got a different failure path: %q", err.Error())
	}
}
