package export

import (
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

func rule(field string, op predicate.Operator, val any) policy.PredicateRule {
	return policy.PredicateRule{
		Field: predicate.NewFieldPath(field),
		Op:    op,
		Value: policy.NewOperand(val),
	}
}

func TestGenerateRego_SimpleAll(t *testing.T) {
	controls := []policy.ControlDefinition{{
		ID:       "CTL.S3.PUBLIC.001",
		Name:     "No Public S3 Bucket Read",
		Severity: policy.SeverityCritical,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				rule("properties.storage.kind", predicate.OpEq, "bucket"),
				rule("properties.storage.access.public_read", predicate.OpEq, true),
			},
		},
	}}

	out := GenerateRego(controls, "stave")

	if !strings.Contains(out, "package stave") {
		t.Error("missing package declaration")
	}
	if !strings.Contains(out, `input.storage.kind == "bucket"`) {
		t.Error("missing kind condition")
	}
	if !strings.Contains(out, "input.storage.access.public_read == true") {
		t.Error("missing public_read condition")
	}
	if !strings.Contains(out, "deny[msg]") {
		t.Error("missing deny rule")
	}
	if !strings.Contains(out, "CTL.S3.PUBLIC.001") {
		t.Error("missing control ID in message")
	}
}

func TestGenerateRego_ComparisonOperators(t *testing.T) {
	controls := []policy.ControlDefinition{{
		ID:       "CTL.TEST.001",
		Name:     "Test Comparisons",
		Severity: policy.SeverityMedium,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				rule("properties.x", predicate.OpNe, "bad"),
				rule("properties.y", predicate.OpGt, float64(25)),
				rule("properties.z", predicate.OpLt, float64(10)),
			},
		},
	}}

	out := GenerateRego(controls, "test")

	if !strings.Contains(out, `input.x != "bad"`) {
		t.Errorf("missing ne operator, got:\n%s", out)
	}
	if !strings.Contains(out, "input.y > 25") {
		t.Errorf("missing gt operator, got:\n%s", out)
	}
	if !strings.Contains(out, "input.z < 10") {
		t.Errorf("missing lt operator, got:\n%s", out)
	}
}

func TestGenerateRego_NestedAny(t *testing.T) {
	controls := []policy.ControlDefinition{{
		ID:       "CTL.IAM.PASSWORD.001",
		Name:     "Password Complexity",
		Severity: policy.SeverityHigh,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				rule("properties.identity.kind", predicate.OpEq, "password_policy"),
				{
					Any: []policy.PredicateRule{
						rule("properties.identity.password_policy.require_uppercase", predicate.OpEq, false),
						rule("properties.identity.password_policy.require_lowercase", predicate.OpEq, false),
					},
				},
			},
		},
	}}

	out := GenerateRego(controls, "stave")

	if !strings.Contains(out, "ctl_iam_password_001_any_") {
		t.Errorf("missing helper rule for nested any, got:\n%s", out)
	}
	if !strings.Contains(out, "require_uppercase == false") {
		t.Error("missing uppercase condition")
	}
	if !strings.Contains(out, "require_lowercase == false") {
		t.Error("missing lowercase condition")
	}
}

func TestGenerateRego_PresentMissing(t *testing.T) {
	controls := []policy.ControlDefinition{{
		ID:       "CTL.TEST.002",
		Name:     "Existence Check",
		Severity: policy.SeverityLow,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				rule("properties.storage.kind", predicate.OpEq, "bucket"),
				{
					Field: predicate.NewFieldPath("properties.storage.tags.compliance"),
					Op:    predicate.OpPresent,
					Value: policy.NewOperand(true),
				},
				{
					Field: predicate.NewFieldPath("properties.storage.access.public_read"),
					Op:    predicate.OpMissing,
					Value: policy.NewOperand(true),
				},
			},
		},
	}}

	out := GenerateRego(controls, "test")

	if !strings.Contains(out, "input.storage.tags.compliance") {
		t.Error("missing present check")
	}
	if !strings.Contains(out, "not input.storage.access.public_read") {
		t.Error("missing missing/not check")
	}
}

func TestGenerateRego_AliasSkipped(t *testing.T) {
	controls := []policy.ControlDefinition{{
		ID:                   "CTL.S3.ACL.001",
		Name:                 "ACL Escalation",
		Severity:             policy.SeverityHigh,
		UnsafePredicateAlias: "s3.has_full_control_grant",
	}}

	out := GenerateRego(controls, "stave")

	if !strings.Contains(out, "Skipped: uses predicate alias") {
		t.Error("alias controls should be skipped with comment")
	}
	if strings.Contains(out, "deny[msg]") {
		t.Error("alias control should not produce a deny rule")
	}
}

func TestGenerateRego_MultipleControls(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:       "CTL.A.001",
			Name:     "First",
			Severity: policy.SeverityHigh,
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					rule("properties.x", predicate.OpEq, true),
				},
			},
		},
		{
			ID:       "CTL.B.001",
			Name:     "Second",
			Severity: policy.SeverityMedium,
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					rule("properties.y", predicate.OpEq, false),
				},
			},
		},
	}

	out := GenerateRego(controls, "multi")

	if !strings.Contains(out, "CTL.A.001") {
		t.Error("missing first control")
	}
	if !strings.Contains(out, "CTL.B.001") {
		t.Error("missing second control")
	}
	if !strings.Contains(out, "Controls: 2") {
		t.Error("missing control count")
	}
}

// Verify the function exists on the unexported type.
var _ = kernel.ControlID("test")
