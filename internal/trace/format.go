package trace

import (
	"fmt"

	"github.com/sufield/stave/internal/domain/predicate"
)

// formatValue produces a human-readable representation of a value.
func formatValue(v any) string {
	if v == nil {
		return "<nil>"
	}
	switch val := v.(type) {
	case string:
		return fmt.Sprintf("%q", val)
	case bool:
		return fmt.Sprintf("%t", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

func resultTag(result bool) string {
	if result {
		return "PASS"
	}
	return "FAIL"
}

// clauseExplanation generates a human-readable explanation from a ClauseNode's data.
func clauseExplanation(c *ClauseNode) string {
	if c.ValueFromParam != "" && c.ResolvedValue == nil {
		return fmt.Sprintf("value_from_param %q not found in params → FAIL", c.ValueFromParam)
	}

	tag := resultTag(c.Result)
	compareValue := c.ResolvedValue

	if !c.FieldExists {
		switch c.Op {
		case predicate.OpMissing:
			return fmt.Sprintf("field absent, missing %v → %s", compareValue, tag)
		case predicate.OpPresent:
			return fmt.Sprintf("field absent, present %v → %s", compareValue, tag)
		case predicate.OpNe:
			return fmt.Sprintf("field absent (absent ne %v is true) → %s", compareValue, tag)
		case predicate.OpListEmpty:
			return fmt.Sprintf("field absent, list_empty %v → %s", compareValue, tag)
		default:
			return fmt.Sprintf("field absent → %s", tag)
		}
	}

	return fmt.Sprintf("%s %s %s → %s", formatValue(c.FieldValue), c.Op, formatValue(compareValue), tag)
}

// fieldRefExplanation generates a human-readable explanation from a FieldRefNode's data.
func fieldRefExplanation(f *FieldRefNode) string {
	tag := resultTag(f.Result)
	if !f.FieldExists {
		return fmt.Sprintf("field absent → %s", tag)
	}
	return fmt.Sprintf("%s %s %s → %s", formatValue(f.FieldValue), f.Op, f.OtherField, tag)
}
