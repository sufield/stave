package policy

import (
	"testing"
)

func TestParseOperator_ChainedModifiers(t *testing.T) {
	t.Parallel()

	op := parseOperator("ForAllValues:ForAnyValue:StringEquals")
	if op != "stringequals" {
		t.Errorf("CRITICAL BUG: parseOperator(\"ForAllValues:ForAnyValue:StringEquals\") = %q, want %q", op, "stringequals")
	}
}
