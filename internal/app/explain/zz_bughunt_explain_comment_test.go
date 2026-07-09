package explain

import (
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestBugHunt_ResolveRuleValue_MisleadingCommentOnMissingParam(t *testing.T) {
	// ValueFromParam is set, but the parameter is missing from the control params.
	r := policy.PredicateRule{
		Field:          predicate.NewFieldPath("properties.x"),
		Op:             predicate.OpEq,
		Value:          policy.Str("default_literal"),
		ValueFromParam: predicate.ParamRef("missing_threshold"),
	}

	val, comment := resolveRuleValue(r, policy.ControlParams{})

	if val != "default_literal" {
		t.Fatalf("expected fallback to literal value 'default_literal', got %v", val)
	}

	// Under the buggy code: the comment still says "value resolved from params.missing_threshold"
	// even though the parameter was not found and we fell back to the literal.
	if strings.Contains(comment, "value resolved from params") {
		t.Errorf("misleading comment: claimed param resolution succeeded when it fell back to literal: %q", comment)
	}
}
