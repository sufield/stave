package ui

import (
	"errors"
	"fmt"
	"testing"

	"github.com/sufield/stave/pkg/stave"
)

// Test_RedGate_IsSentinelFacade asserts the CORRECT behavior for
// error.go:222 IsSentinel: errors wrapping the public facade sentinels
// stave.ErrFailingTests and stave.ErrInvalidInput must be recognised as
// sentinels.
//
// ExitCode (error.go:103-117) already classifies these wrapped sentinels
// into ExitInputError(2) / ExitViolations(3). IsSentinel is the predicate
// the executor (cmd/executor.go handleExecutionError) uses to decide
// whether to SUPPRESS the structured stderr banner, and
// resolvePrimaryErrorSignal uses it to pick the presentation template.
// If IsSentinel returns false for these, the executor prints a second
// "[ERR] Command failed (INTERNAL_ERROR)" banner on top of output the
// command already wrote, with INTERNAL_ERROR semantics that contradict
// the real exit code (3 for ErrFailingTests, 2 for ErrInvalidInput).
//
// This test FAILS against current code because IsSentinel omits both
// public facade sentinels from its errors.Is chain.
func Test_RedGate_IsSentinelFacade(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()

	cases := []struct {
		name         string
		err          error
		wantExitCode int
	}{
		{
			name:         "wrap stave.ErrFailingTests",
			err:          fmt.Errorf("control tests: %w", stave.ErrFailingTests),
			wantExitCode: ExitViolations,
		},
		{
			name:         "wrap stave.ErrInvalidInput",
			err:          fmt.Errorf("--format must be json: %w", stave.ErrInvalidInput),
			wantExitCode: ExitInputError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Cross-check: ExitCode already treats these as classified,
			// non-internal outcomes. This anchors the contract — the
			// error is NOT an internal failure.
			if got := ExitCode(tc.err); got != tc.wantExitCode {
				t.Fatalf("ExitCode(%v) = %d, want %d (anchor)", tc.err, got, tc.wantExitCode)
			}
			if got := ExitCode(tc.err); got == ExitInternal {
				t.Fatalf("ExitCode classified %v as ExitInternal; sanity anchor broken", tc.err)
			}

			// CORRECT behavior: an error wrapping a public facade
			// sentinel IS a platform sentinel, so the executor can
			// suppress the redundant INTERNAL_ERROR banner.
			if !IsSentinel(tc.err) {
				t.Fatalf("IsSentinel(%v) = false, want true: error wrapping a public facade sentinel "+
					"must be recognised as a sentinel so the executor suppresses the contradictory "+
					"INTERNAL_ERROR banner (ExitCode reports %d, not ExitInternal)",
					tc.err, tc.wantExitCode)
			}
		})
	}

	// Bare sentinels (not wrapped) must also be recognised.
	if !IsSentinel(stave.ErrFailingTests) {
		t.Fatalf("IsSentinel(stave.ErrFailingTests) = false, want true")
	}
	if !IsSentinel(stave.ErrInvalidInput) {
		t.Fatalf("IsSentinel(stave.ErrInvalidInput) = false, want true")
	}

	// Guard against a tautological test: confirm errors.Is wiring on the
	// public sentinels behaves as expected (so a false IsSentinel result
	// is a real defect, not a broken wrap).
	if !errors.Is(fmt.Errorf("x: %w", stave.ErrFailingTests), stave.ErrFailingTests) {
		t.Fatalf("errors.Is wrap chain broken for ErrFailingTests; test setup invalid")
	}
}
