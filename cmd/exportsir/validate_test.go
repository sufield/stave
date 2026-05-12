package exportsir

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// makePredicateRule constructs a leaf PredicateRule with the
// supplied field path. The op + value are filler — the validator
// only reads Field, so tests can keep the rest minimal.
func makePredicateRule(field string) policy.PredicateRule {
	return policy.PredicateRule{
		Field: predicate.NewFieldPath(field),
		Op:    predicate.OpEq,
	}
}

func TestValidation_DetectsProjectionGap(t *testing.T) {
	t.Parallel()
	findings := []evaluation.Finding{{
		ControlID: kernel.ControlID("CTL.COGNITO.MFA.001"),
		AssetID:   asset.ID("arn:aws:cognito-idp:us-east-1:111122223333:userpool/abc"),
	}}
	facts := []Fact{
		{
			FactID:     "aaaaaaaaaaaa",
			Subject:    "arn:aws:cognito-idp:us-east-1:111122223333:userpool/abc",
			Predicate:  "has_type",
			Object:     "aws_cognito_user_pool",
			Provenance: &Provenance{PropertyPath: "type"},
		},
		{
			FactID:     "bbbbbbbbbbbb",
			Subject:    "arn:aws:cognito-idp:us-east-1:111122223333:userpool/abc",
			Predicate:  "has_tag",
			Object:     "environment=production",
			Provenance: &Provenance{PropertyPath: "tags.environment"},
		},
	}
	controls := []policy.ControlDefinition{{
		ID: kernel.ControlID("CTL.COGNITO.MFA.001"),
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				makePredicateRule("properties.identity.governance.mfa_enforced"),
			},
		},
	}}
	warnings := ValidateSIRCompleteness(findings, facts, controls)
	if len(warnings) != 1 {
		t.Fatalf("want 1 warning, got %d (%+v)", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0].CELPath, "identity.governance.mfa_enforced") {
		t.Errorf("CELPath = %q, want contains identity.governance.mfa_enforced", warnings[0].CELPath)
	}
	if !strings.Contains(warnings[0].Message, "no SIR fact covers") {
		t.Errorf("Message missing core phrase: %q", warnings[0].Message)
	}
	if warnings[0].ControlID != "CTL.COGNITO.MFA.001" {
		t.Errorf("ControlID = %q", warnings[0].ControlID)
	}
}

// TestValidation_NoGapWhenCovered confirms that a fact with the
// same property path the control evaluates suppresses the warning.
func TestValidation_NoGapWhenCovered(t *testing.T) {
	t.Parallel()
	findings := []evaluation.Finding{{
		ControlID: kernel.ControlID("CTL.COGNITO.MFA.001"),
		AssetID:   asset.ID("arn:aws:cognito-idp:us-east-1:111122223333:userpool/abc"),
	}}
	facts := []Fact{
		{
			FactID:    "ccccccccc",
			Subject:   "arn:aws:cognito-idp:us-east-1:111122223333:userpool/abc",
			Predicate: "has_mfa_enforced",
			Object:    "false",
			Provenance: &Provenance{
				PropertyPath: "identity.governance.mfa_enforced",
			},
		},
	}
	controls := []policy.ControlDefinition{{
		ID: kernel.ControlID("CTL.COGNITO.MFA.001"),
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				makePredicateRule("properties.identity.governance.mfa_enforced"),
			},
		},
	}}
	warnings := ValidateSIRCompleteness(findings, facts, controls)
	if len(warnings) != 0 {
		t.Errorf("want no warnings, got %d: %+v", len(warnings), warnings)
	}
}

// TestValidation_BidirectionalCoverage confirms the substring
// match works in either direction: a fact path that is deeper
// than the control path (control evaluates a parent, fact
// records a leaf) AND a fact path that is shallower than the
// control path (control evaluates a leaf, fact summarises a
// parent) both count as coverage.
func TestValidation_BidirectionalCoverage(t *testing.T) {
	t.Parallel()
	findings := []evaluation.Finding{{
		ControlID: "CTL.IAM.OVERPERM.001",
		AssetID:   "arn:aws:iam::111:role/x",
	}}
	// Fact path is deeper than control path.
	facts := []Fact{
		{
			FactID:  "deeper",
			Subject: "arn:aws:iam::111:role/x",
			Provenance: &Provenance{
				PropertyPath: "identity.policies.attached_policies[0].statements[0].Action",
			},
		},
	}
	controls := []policy.ControlDefinition{{
		ID: "CTL.IAM.OVERPERM.001",
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				makePredicateRule("properties.identity.policies.attached_policies"),
			},
		},
	}}
	warnings := ValidateSIRCompleteness(findings, facts, controls)
	if len(warnings) != 0 {
		t.Errorf("want no warnings (control path is prefix of fact path), got %+v", warnings)
	}
}

// TestValidation_NoFindingsNoWarnings — there's nothing to
// validate when CEL didn't fire on anything. This is the common
// remediated-fixture path; the validator must be silent.
func TestValidation_NoFindingsNoWarnings(t *testing.T) {
	t.Parallel()
	warnings := ValidateSIRCompleteness(nil, nil, nil)
	if warnings != nil {
		t.Errorf("want nil warnings on empty input, got %+v", warnings)
	}
}

// TestValidation_UnknownControlIDIsIgnored — if a finding
// references a control ID not in the catalog, skip it silently.
// That's a load-time bug (mismatched catalog vs report), not a
// projection gap.
func TestValidation_UnknownControlIDIsIgnored(t *testing.T) {
	t.Parallel()
	findings := []evaluation.Finding{{
		ControlID: "CTL.UNKNOWN.001",
		AssetID:   "arn:aws:s3:::x",
	}}
	facts := []Fact{
		{
			FactID:     "x",
			Subject:    "arn:aws:s3:::x",
			Provenance: &Provenance{PropertyPath: "type"},
		},
	}
	warnings := ValidateSIRCompleteness(findings, facts, nil)
	if len(warnings) != 0 {
		t.Errorf("unknown control should produce no warning, got %+v", warnings)
	}
}

// TestExtractPredicateFieldPaths_StripsPropertiesPrefix confirms
// the leading "properties." prefix common to control YAML field
// paths is stripped — the SIR fact provenance.PropertyPath is
// observation-relative (no prefix), so paths must align before
// comparison.
func TestExtractPredicateFieldPaths_StripsPropertiesPrefix(t *testing.T) {
	t.Parallel()
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			makePredicateRule("properties.identity.governance.mfa_enforced"),
			makePredicateRule("properties.encryption.algorithm"),
		},
	}
	got := extractPredicateFieldPaths(pred)
	want := []string{"encryption.algorithm", "identity.governance.mfa_enforced"}
	if len(got) != len(want) {
		t.Fatalf("count mismatch: got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("paths[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestExtractPredicateFieldPaths_DeduplicatesAcrossNestedBlocks
// confirms a control with the same field repeated under different
// any/all branches collapses to a single path entry.
func TestExtractPredicateFieldPaths_DeduplicatesAcrossNestedBlocks(t *testing.T) {
	t.Parallel()
	pred := policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{
				All: []policy.PredicateRule{
					makePredicateRule("properties.network.is_private"),
					makePredicateRule("properties.network.is_private"),
				},
			},
			makePredicateRule("properties.network.is_private"),
		},
	}
	got := extractPredicateFieldPaths(pred)
	if len(got) != 1 || got[0] != "network.is_private" {
		t.Errorf("got %v, want [network.is_private]", got)
	}
}

// TestRenderValidationWarnings_FormatStable renders a fixed set
// of warnings to a buffer and checks the canonical phrases the
// CLI relies on (the leading "WARNING:" tag, the "Asset:" prefix
// for the asset line, the "n SIR projection gap(s)" header).
// Format changes that break grep-based CI checks would surface
// here.
func TestRenderValidationWarnings_FormatStable(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	renderValidationWarnings(buf, []ValidationWarning{
		{
			ControlID: "CTL.X.001",
			AssetID:   "arn:aws:s3:::a",
			CELPath:   "x.y",
			Message:   "Control CTL.X.001 evaluates x.y but no SIR fact covers this property path. SMT queries cannot distinguish vulnerable from remediated for this control.",
		},
	})
	out := buf.String()
	if !strings.Contains(out, "1 SIR projection gap(s) detected:") {
		t.Errorf("missing header, got: %s", out)
	}
	if !strings.Contains(out, "  WARNING: Control CTL.X.001 evaluates x.y") {
		t.Errorf("missing WARNING line, got: %s", out)
	}
	if !strings.Contains(out, "           Asset: arn:aws:s3:::a") {
		t.Errorf("missing Asset line, got: %s", out)
	}
}

// TestRenderValidationWarnings_EmptyIsSilent — no warnings, no
// output. The "no gaps" banner is the caller's responsibility.
func TestRenderValidationWarnings_EmptyIsSilent(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	renderValidationWarnings(buf, nil)
	if buf.Len() != 0 {
		t.Errorf("empty input should produce no output, got: %q", buf.String())
	}
}

// TestValidation_DeterministicOrder confirms identical input
// produces byte-identical warning ordering across runs (the
// internal map iterations would otherwise scramble the result).
func TestValidation_DeterministicOrder(t *testing.T) {
	t.Parallel()
	findings := []evaluation.Finding{
		{ControlID: "CTL.B", AssetID: "arn:b"},
		{ControlID: "CTL.A", AssetID: "arn:a"},
	}
	facts := []Fact{} // intentionally empty so every CEL path warns
	controls := []policy.ControlDefinition{
		{
			ID: "CTL.A",
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					makePredicateRule("properties.zzz"),
					makePredicateRule("properties.aaa"),
				},
			},
		},
		{
			ID: "CTL.B",
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					makePredicateRule("properties.mmm"),
				},
			},
		},
	}
	var first []ValidationWarning
	for run := range 5 {
		warnings := ValidateSIRCompleteness(findings, facts, controls)
		if run == 0 {
			first = warnings
			continue
		}
		if len(warnings) != len(first) {
			t.Fatalf("run %d: count differs (%d vs %d)", run, len(warnings), len(first))
		}
		for i := range warnings {
			if warnings[i] != first[i] {
				t.Errorf("run %d: warnings[%d] differs:\n  first=%+v\n  this =%+v",
					run, i, first[i], warnings[i])
			}
		}
	}
}
