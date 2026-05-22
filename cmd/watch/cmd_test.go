// Package watch tests. This file holds regression tests for the
// subprocess-result interpretation contract owned by
// parseAssessResult — the post-subprocess invariants the watch loop
// relies on. Each test name encodes the invariant it locks in.
package watch

import (
	"errors"
	"strings"
	"testing"
)

// TestParseAssessResult_EmptyStdoutOnSuccessfulExitIsAnError is the
// load-bearing regression guard for the original bug: an exit code
// in {0, 3} with empty stdout MUST surface as an error, not an
// implicit COMPLIANT. The pre-fix code returned ("COMPLIANT", 0, …,
// nil) here, which masked a recovered-panic evaluator regression as
// a clean-state alert downstream. If a future contributor "fixes"
// this back to a permissive default, this test catches it.
func TestParseAssessResult_EmptyStdoutOnSuccessfulExitIsAnError(t *testing.T) {
	for _, exitCode := range []int{0, 3} {
		t.Run("exit_"+itoa(exitCode), func(t *testing.T) {
			state, viol, sla, dwell, ids, err := parseAssessResult(
				nil,
				[]byte("stave apply: internal error\n"),
				exitCode,
				nil, // spawnErr nil — subprocess actually ran
			)
			if err == nil {
				t.Fatalf("expected error for empty stdout on exit %d; got state=%q viol=%d", exitCode, state, viol)
			}
			if state != "" {
				t.Errorf("state must be empty on error path, got %q", state)
			}
			if state == "COMPLIANT" {
				t.Errorf("state must NEVER be COMPLIANT when stdout is empty — this is the regression we are guarding against")
			}
			if viol != 0 || sla != 0 || dwell != 0 || ids != nil {
				t.Errorf("counts must be zero on error path; got viol=%d sla=%d dwell=%f ids=%v", viol, sla, dwell, ids)
			}
			// Error message must name the exit code and include
			// the stderr — operators rely on this to diagnose the
			// upstream evaluator regression.
			msg := err.Error()
			if !strings.Contains(msg, "no output on stdout") {
				t.Errorf("error should explain the missing-output contract violation, got: %q", msg)
			}
			if !strings.Contains(msg, "internal error") {
				t.Errorf("error should include stderr context, got: %q", msg)
			}
		})
	}
}

// TestParseAssessResult_SpawnTimeFailureSurfaces — when classifyRunErr
// determines the subprocess never actually ran (binary not found,
// context cancellation, etc.) the spawnErr is non-nil and the
// result must surface as "failed to launch assessment". Invariant 1.
func TestParseAssessResult_SpawnTimeFailureSurfaces(t *testing.T) {
	spawnErr := errors.New("exec: \"stave\": executable file not found in $PATH")
	_, _, _, _, _, err := parseAssessResult(nil, nil, 0, spawnErr)
	if err == nil {
		t.Fatal("expected error for spawn-time failure")
	}
	if !strings.Contains(err.Error(), "failed to launch") {
		t.Errorf("error should signal spawn failure, got: %q", err.Error())
	}
	if !errors.Is(err, spawnErr) {
		t.Errorf("error should wrap the original spawn error, got: %v", err)
	}
}

// TestParseAssessResult_NonSuccessfulExitCodesAreErrors — exit codes
// outside {0, 3} surface as errors regardless of stdout content.
// Invariant 2.
func TestParseAssessResult_NonSuccessfulExitCodesAreErrors(t *testing.T) {
	for _, exitCode := range []int{2, 4, 130, 1, 99} {
		t.Run("exit_"+itoa(exitCode), func(t *testing.T) {
			_, _, _, _, _, err := parseAssessResult(
				[]byte(`{"status":"NON_COMPLIANT"}`), // even with valid JSON
				[]byte("input error: missing observations"),
				exitCode,
				nil,
			)
			if err == nil {
				t.Fatalf("expected error for exit %d", exitCode)
			}
			if !strings.Contains(err.Error(), "terminated by system") {
				t.Errorf("error should classify as system termination, got: %q", err.Error())
			}
		})
	}
}

// TestParseAssessResult_HappyPathParsesJSON — exit 0 or 3 with a
// well-formed JSON payload returns the parsed state and counts
// without error. Sanity check that the surrounding tests don't
// accidentally gate the success path.
func TestParseAssessResult_HappyPathParsesJSON(t *testing.T) {
	payload := []byte(`{
		"status": "COMPLIANT",
		"summary": {"violations": 0},
		"findings": [],
		"risk_signals": [],
		"top_exposures": []
	}`)
	state, viol, sla, dwell, ids, err := parseAssessResult(payload, nil, 0, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != "COMPLIANT" {
		t.Errorf("state: got %q, want COMPLIANT", state)
	}
	if viol != 0 || sla != 0 || dwell != 0 || len(ids) != 0 {
		t.Errorf("counts should be zero on the COMPLIANT path; got viol=%d sla=%d dwell=%f ids=%v", viol, sla, dwell, ids)
	}
}

// TestParseAssessResult_MalformedJSONIsAnError — exit 0 or 3 with
// stdout that isn't valid JSON surfaces as a parse error. This is
// the closest neighbour of the empty-stdout case and must not be
// conflated with it.
func TestParseAssessResult_MalformedJSONIsAnError(t *testing.T) {
	_, _, _, _, _, err := parseAssessResult(
		[]byte("not json at all\n"), nil, 0, nil,
	)
	if err == nil {
		t.Fatal("expected parse error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "parse assessment output") {
		t.Errorf("error should signal a parse failure, got: %q", err.Error())
	}
}

// TestClassifyRunErr — narrow tests of the runErr→exit-code split.
// classifyRunErr is the seam that makes parseAssessResult testable
// without fabricating an *exec.ExitError; lock its behaviour in too.
func TestClassifyRunErr(t *testing.T) {
	t.Run("nil_err_means_exit_0", func(t *testing.T) {
		code, spawn := classifyRunErr(nil)
		if code != 0 || spawn != nil {
			t.Errorf("nil error: got (code=%d, spawn=%v); want (0, nil)", code, spawn)
		}
	})
	t.Run("non_exit_error_becomes_spawn_failure", func(t *testing.T) {
		want := errors.New("fork/exec /bin/stave: no such file or directory")
		code, spawn := classifyRunErr(want)
		if code != 0 {
			t.Errorf("exit code on spawn failure: got %d, want 0", code)
		}
		if !errors.Is(spawn, want) {
			t.Errorf("spawn error should be the original: got %v", spawn)
		}
	})
	// We don't test the *exec.ExitError branch here — that requires
	// fabricating an *os.ProcessState, which is the whole reason
	// classifyRunErr was extracted. Coverage of that branch comes
	// from the e2e tests in cmd/stave/ that actually spawn the
	// binary.
}

// itoa avoids importing strconv just to format an exit code in a
// t.Run subtest name — keeps the test file's dependency surface
// minimal.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Compile-time guards: if either symbol is renamed without updating
// the tests, the build catches it before the tests run.
var (
	_ = parseAssessResult
	_ = classifyRunErr
)
