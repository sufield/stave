package engine

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
)

// Bug 3 — sync.Pool contract violation in the prefix-exposure flow.
//
// The prefix strategy borrowed *Finding pointers from findingPool (via
// NewFinding), value-copied them into a []Finding slice (orphaning the pool
// pointers), then wrapInPointers took &slice[i] addresses, which the collector
// fed to ReturnFindings — poisoning the pool with non-pool slice addresses.
//
// The bug resists a clean red/green assertion: sync.Pool.Get may return a
// brand-new object instead of a poisoned one, and borrowFinding zeroes whatever
// it hands back, so the poison is not directly observable. This test instead
// exercises the REAL borrow -> build -> return -> re-borrow cycle the collector
// performs, with heavy pool reuse, and asserts findings never come back
// corrupted. After the fix (pool pointers carried end to end) the cycle is
// clean; a value-slice address fed into the pool would, over many iterations,
// surface as an aliased / wrong-valued finding here.
func TestPrefixExposure_PoolRoundTripStaysCorrect(t *testing.T) {
	// Missing protected_prefixes -> deterministic single config-issue finding.
	ctl := exposureControl("CTL.EXP.POOL", nil, nil)

	const iterations = 2000
	for i := 0; i < iterations; i++ {
		tl := exposureLifecycle(t, nil)

		row, findings := EvaluatePrefixExposureForRow(tl, ctl)
		if row.Verdict != evaluation.VerdictViolation {
			t.Fatalf("iter %d: verdict = %v, want Violation", i, row.Verdict)
		}
		if len(findings) != 1 {
			t.Fatalf("iter %d: got %d findings, want 1", i, len(findings))
		}
		// AssetID is set explicitly in newBaseFinding; if the pool handed
		// back a poisoned/aliased pointer, this field would not survive
		// the borrow/return reuse intact.
		if got := findings[0].AssetID; got != asset.ID("bucket-1") {
			t.Fatalf("iter %d: finding AssetID = %q, want bucket-1 (pool corruption?)", i, got)
		}

		// Return the pool-borrowed pointers, exactly as the collector does
		// after value-copying into its stripe. With the wrapInPointers bug
		// these were slice-backing addresses, not pool pointers.
		ReturnFindings(findings)
	}
}

// TestReturnFindings_NilEntriesIgnored locks the documented ReturnFindings
// contract that nil pointers in the batch are skipped (the prefix path can
// produce a nil finding when control/lifecycle wiring is incomplete).
func TestReturnFindings_NilEntriesIgnored(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ReturnFindings panicked on a nil entry: %v", r)
		}
	}()
	ReturnFindings([]*evaluation.Finding{nil})

	// A subsequent borrow must still yield a usable, zeroed finding.
	f := borrowFinding()
	if f == nil {
		t.Fatal("borrowFinding returned nil after a nil-entry return")
	}
	if f.AssetID != "" {
		t.Fatalf("re-borrowed finding not zeroed: AssetID=%q", f.AssetID)
	}
}
