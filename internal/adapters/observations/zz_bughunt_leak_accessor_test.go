package observations

import "testing"

// TestBugHunt_LeakedReadGoroutinesAccessor verifies that the exported
// accessor documented in leak_metrics.go actually exists and reflects
// increments recorded via the private recordLeakedReadGoroutine().
//
// The package doc promises operators and test harnesses can call
// LeakedReadGoroutines() to read the ctx-cancelled-leaked-read-goroutine
// counter, but the function was never implemented. Before the fix this
// file fails to COMPILE (undefined: LeakedReadGoroutines) = RED.
func TestBugHunt_LeakedReadGoroutinesAccessor(t *testing.T) {
	before := LeakedReadGoroutines()

	const n = 3
	for range n {
		recordLeakedReadGoroutine()
	}

	after := LeakedReadGoroutines()
	if got := after - before; got != n {
		t.Fatalf("LeakedReadGoroutines() delta = %d, want %d (before=%d, after=%d)",
			got, n, before, after)
	}
}
