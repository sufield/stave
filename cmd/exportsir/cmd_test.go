package exportsir

import (
	"bytes"
	"strings"
	"testing"
)

// TestRun_RejectsUnknownFormat asserts the early flag-validation
// path: an unknown --format value fails fast (exit 2 via
// ui.UserError) before any evaluation is attempted.
func TestRun_RejectsUnknownFormat(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	err := run(t.Context(), &buf, &bytes.Buffer{}, &options{Format: "yaml"})
	if err == nil {
		t.Fatalf("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "--format must be one of") {
		t.Errorf("error should explain format: got %q", err.Error())
	}
}

// TestRun_RejectsMalformedNow asserts the early validation of
// --now: a non-RFC3339 string fails fast with an actionable
// message instead of producing nonsense output. Pinning --now is
// the determinism gate; rejecting a bad value here protects every
// downstream consumer.
func TestRun_RejectsMalformedNow(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	err := run(t.Context(), &buf, &bytes.Buffer{}, &options{Format: "json", Now: "not-a-time"})
	if err == nil {
		t.Fatalf("expected error for malformed --now")
	}
	if !strings.Contains(err.Error(), "RFC3339") {
		t.Errorf("error should mention RFC3339: got %q", err.Error())
	}
}

// TestRun_RejectsUnknownAllowlistMode asserts the new flag's
// validation: only "curated" and "full" are accepted. A misspelling
// fails fast before evaluation rather than silently defaulting to
// one mode or the other.
func TestRun_RejectsUnknownAllowlistMode(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	err := run(t.Context(), &buf, &bytes.Buffer{}, &options{Format: "json", AllowlistMode: "everything"})
	if err == nil {
		t.Fatalf("expected error for unknown allowlist mode")
	}
	if !strings.Contains(err.Error(), "--allowlist-mode must be curated | full") {
		t.Errorf("error should explain mode: got %q", err.Error())
	}
}

// What integration coverage moved
//
// The prior version of this file carried two tests that exercised
// the full run() pipeline against hand-built snapshots:
//
//   TestRun_EmitsSIRJSONWithCrossAccountRoleHops — asserted that
//      iamPolicyFacts emits cross_account=true on a transitive
//      role hop fixture.
//   TestRun_ProducesByteIdenticalOutputAcrossRuns — asserted the
//      SIR projection is deterministic.
//
// Both tests' logic now lives in internal/core/sirfacts/, where
// it has dedicated unit coverage:
//
//   sirfacts.TestExtractFacts_EmitsCrossAccountTriple
//   sirfacts.TestSerializeJSONL_Deterministic
//   sirfacts.TestSerializeSMT2_*
//
// cmd/exportsir's tests are now CLI-flag-validation only. End-to-end
// behaviour is covered by the e2e suite under testdata/e2e/, which
// runs the real stave binary against shipped fixtures.
