package cliapi

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
	"github.com/sufield/stave/internal/core/sirfacts"
)

// These exercise the SIR validation helpers that moved here from
// cmd/exportsir.

func makePredicateRule(field string) policy.PredicateRule {
	return policy.PredicateRule{
		Field: predicate.NewFieldPath(field),
		Op:    predicate.OpEq,
	}
}

func TestValidation_DetectsProjectionGap(t *testing.T) {
	findings := []evaluation.Finding{{
		ControlID: kernel.ControlID("CTL.COGNITO.MFA.001"),
		AssetID:   asset.ID("arn:aws:cognito-idp:us-east-1:111122223333:userpool/abc"),
	}}
	facts := []sirfacts.Fact{
		{
			FactID:     "aaaaaaaaaaaa",
			Subject:    "arn:aws:cognito-idp:us-east-1:111122223333:userpool/abc",
			Predicate:  "has_type",
			Object:     "aws_cognito_user_pool",
			Provenance: &sirfacts.Provenance{PropertyPath: "type"},
		},
		{
			FactID:     "bbbbbbbbbbbb",
			Subject:    "arn:aws:cognito-idp:us-east-1:111122223333:userpool/abc",
			Predicate:  "has_tag",
			Object:     "environment=production",
			Provenance: &sirfacts.Provenance{PropertyPath: "tags.environment"},
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

func TestValidation_NoGapWhenCovered(t *testing.T) {
	findings := []evaluation.Finding{{
		ControlID: kernel.ControlID("CTL.COGNITO.MFA.001"),
		AssetID:   asset.ID("arn:aws:cognito-idp:us-east-1:111122223333:userpool/abc"),
	}}
	facts := []sirfacts.Fact{{
		FactID:     "ccccccccc",
		Subject:    "arn:aws:cognito-idp:us-east-1:111122223333:userpool/abc",
		Predicate:  "has_mfa_enforced",
		Object:     "false",
		Provenance: &sirfacts.Provenance{PropertyPath: "identity.governance.mfa_enforced"},
	}}
	controls := []policy.ControlDefinition{{
		ID: kernel.ControlID("CTL.COGNITO.MFA.001"),
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				makePredicateRule("properties.identity.governance.mfa_enforced"),
			},
		},
	}}
	if warnings := ValidateSIRCompleteness(findings, facts, controls); len(warnings) != 0 {
		t.Errorf("want no warnings, got %d: %+v", len(warnings), warnings)
	}
}

func TestValidation_BidirectionalCoverage(t *testing.T) {
	findings := []evaluation.Finding{{ControlID: "CTL.IAM.OVERPERM.001", AssetID: "arn:aws:iam::111:role/x"}}
	facts := []sirfacts.Fact{{
		FactID:     "deeper",
		Subject:    "arn:aws:iam::111:role/x",
		Provenance: &sirfacts.Provenance{PropertyPath: "identity.policies.attached_policies[0].statements[0].Action"},
	}}
	controls := []policy.ControlDefinition{{
		ID: "CTL.IAM.OVERPERM.001",
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{makePredicateRule("properties.identity.policies.attached_policies")},
		},
	}}
	if warnings := ValidateSIRCompleteness(findings, facts, controls); len(warnings) != 0 {
		t.Errorf("want no warnings (control path is prefix of fact path), got %+v", warnings)
	}
}

func TestValidation_NoFindingsNoWarnings(t *testing.T) {
	if warnings := ValidateSIRCompleteness(nil, nil, nil); warnings != nil {
		t.Errorf("want nil warnings on empty input, got %+v", warnings)
	}
}

func TestValidation_UnknownControlIDIsIgnored(t *testing.T) {
	findings := []evaluation.Finding{{ControlID: "CTL.UNKNOWN.001", AssetID: "arn:aws:s3:::x"}}
	facts := []sirfacts.Fact{{
		FactID:     "x",
		Subject:    "arn:aws:s3:::x",
		Provenance: &sirfacts.Provenance{PropertyPath: "type"},
	}}
	if warnings := ValidateSIRCompleteness(findings, facts, nil); len(warnings) != 0 {
		t.Errorf("unknown control should produce no warning, got %+v", warnings)
	}
}

func TestExtractPredicateFieldPaths_StripsPropertiesPrefix(t *testing.T) {
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

func TestExtractPredicateFieldPaths_DeduplicatesAcrossNestedBlocks(t *testing.T) {
	pred := policy.UnsafePredicate{
		Any: []policy.PredicateRule{
			{All: []policy.PredicateRule{
				makePredicateRule("properties.network.is_private"),
				makePredicateRule("properties.network.is_private"),
			}},
			makePredicateRule("properties.network.is_private"),
		},
	}
	got := extractPredicateFieldPaths(pred)
	if len(got) != 1 || got[0] != "network.is_private" {
		t.Errorf("got %v, want [network.is_private]", got)
	}
}

// TestRenderSIRValidation_FormatStable checks the grep-relied-on phrases
// for the gap report (the renderer now also emits the no-gaps banner).
func TestRenderSIRValidation_FormatStable(t *testing.T) {
	out := string(renderSIRValidation([]ValidationWarning{{
		ControlID: "CTL.X.001",
		AssetID:   "arn:aws:s3:::a",
		CELPath:   "x.y",
		Message:   "Control CTL.X.001 evaluates x.y but no SIR fact covers this property path. SMT queries cannot distinguish vulnerable from remediated for this control.",
	}}))
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

// TestRenderSIRValidation_EmptyShowsBanner — no gaps emits the all-clear
// banner (the command writes it to stderr only when --validate is set).
func TestRenderSIRValidation_EmptyShowsBanner(t *testing.T) {
	out := string(renderSIRValidation(nil))
	if !strings.Contains(out, "all CEL-evaluated properties are projected. No gaps.") {
		t.Errorf("empty input should show the no-gaps banner, got: %q", out)
	}
}

func TestValidation_DeterministicOrder(t *testing.T) {
	findings := []evaluation.Finding{
		{ControlID: "CTL.B", AssetID: "arn:b"},
		{ControlID: "CTL.A", AssetID: "arn:a"},
	}
	facts := []sirfacts.Fact{}
	controls := []policy.ControlDefinition{
		{ID: "CTL.A", UnsafePredicate: policy.UnsafePredicate{All: []policy.PredicateRule{
			makePredicateRule("properties.zzz"),
			makePredicateRule("properties.aaa"),
		}}},
		{ID: "CTL.B", UnsafePredicate: policy.UnsafePredicate{All: []policy.PredicateRule{
			makePredicateRule("properties.mmm"),
		}}},
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
				t.Errorf("run %d: warnings[%d] differs", run, i)
			}
		}
	}
}
