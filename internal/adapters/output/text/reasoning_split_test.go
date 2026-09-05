package text

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

// TestWriteFindingReasoning_SplitSections confirms that a finding
// with mixed gate and unsafe-match clauses renders the gates under
// "Scope:" and the unsafe-match clauses under "Reasoning:" — the
// audit's sub-bug 2 fix.
func TestWriteFindingReasoning_SplitSections(t *testing.T) {
	f := remediation.Finding{
		ReasoningTrace: []evaluation.MatchedClause{
			{ObservationKey: "storage.kind", Operator: "eq", ExpectedValue: "bucket", ObservedValue: "bucket"},
			{ObservationKey: "storage.access.public_read", Operator: "eq", ExpectedValue: true, ObservedValue: true},
			{ObservationKey: "protected_prefix", Operator: "eq", ExpectedValue: "backups/", ObservedValue: "backups/"},
			{ObservationKey: "storage.controls.public_access_block.block_public_acls", Operator: "eq", ExpectedValue: false, ObservedValue: false},
		}}

	var buf bytes.Buffer
	d := &drawer{w: &buf}
	writeFindingReasoning(d, &f)
	out := buf.String()

	// Scope section must come first.
	scopeIdx := strings.Index(out, "Scope:")
	reasIdx := strings.Index(out, "Reasoning:")
	if scopeIdx < 0 || reasIdx < 0 {
		t.Fatalf("output missing Scope/Reasoning section:\n%s", out)
	}
	if scopeIdx >= reasIdx {
		t.Errorf("Scope must precede Reasoning in output:\n%s", out)
	}

	// Gates under Scope; violations under Reasoning.
	scopeBlock := out[scopeIdx:reasIdx]
	reasBlock := out[reasIdx:]

	if !strings.Contains(scopeBlock, "storage.kind") {
		t.Errorf("storage.kind (gate) should appear under Scope:\n%s", out)
	}
	if !strings.Contains(scopeBlock, "protected prefix") {
		t.Errorf("protected_prefix (gate) should appear under Scope:\n%s", out)
	}
	if !strings.Contains(reasBlock, "the bucket allows anonymous read") {
		t.Errorf("storage.access.public_read (unsafe-match) should appear under Reasoning:\n%s", out)
	}
	if !strings.Contains(reasBlock, "BlockPublicAcls") {
		t.Errorf("BlockPublicAcls (unsafe-match) should appear under Reasoning:\n%s", out)
	}

	// Sub-bug 1 regression: no contradiction shape anywhere in output.
	if strings.Contains(out, "must equal") || strings.Contains(out, "but is") {
		t.Errorf("output contains contradiction-shape wording:\n%s", out)
	}
}

// TestWriteFindingReasoning_OnlyUnsafeMatch confirms output is silent
// about the Scope section when no gates fire.
func TestWriteFindingReasoning_OnlyUnsafeMatch(t *testing.T) {
	f := remediation.Finding{
		ReasoningTrace: []evaluation.MatchedClause{
			{ObservationKey: "storage.access.public_read", Operator: "eq", ExpectedValue: true, ObservedValue: true},
		}}

	var buf bytes.Buffer
	d := &drawer{w: &buf}
	writeFindingReasoning(d, &f)
	out := buf.String()

	if strings.Contains(out, "Scope:") {
		t.Errorf("output should not include Scope section when no gates present:\n%s", out)
	}
	if !strings.Contains(out, "Reasoning:") {
		t.Errorf("output missing Reasoning section:\n%s", out)
	}
}

// TestWriteFindingReasoning_OnlyGate confirms output is silent about
// the Reasoning section when only gates fire (degenerate case).
func TestWriteFindingReasoning_OnlyGate(t *testing.T) {
	f := remediation.Finding{
		ReasoningTrace: []evaluation.MatchedClause{
			{ObservationKey: "storage.kind", Operator: "eq", ExpectedValue: "bucket", ObservedValue: "bucket"},
		}}

	var buf bytes.Buffer
	d := &drawer{w: &buf}
	writeFindingReasoning(d, &f)
	out := buf.String()

	if strings.Contains(out, "Reasoning:") {
		t.Errorf("output should not include Reasoning section when only gates present:\n%s", out)
	}
	if !strings.Contains(out, "Scope:") {
		t.Errorf("output missing Scope section:\n%s", out)
	}
}
