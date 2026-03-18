package trace

import (
	"fmt"

	"github.com/sufield/stave/internal/domain/predicate"
)

// maxValueLen caps formatted values in trace explanations so that large
// payloads (e.g. inline IAM policy JSON) don't make the output unreadable.
const maxValueLen = 120

// formatValue produces a human-readable representation of a value,
// truncating results that exceed maxValueLen.
func formatValue(v any) string {
	if v == nil {
		return "<nil>"
	}
	var s string
	switch val := v.(type) {
	case string:
		s = fmt.Sprintf("%q", val)
	case bool:
		s = fmt.Sprintf("%t", val)
	default:
		s = fmt.Sprintf("%v", val)
	}
	if len(s) > maxValueLen {
		return s[:maxValueLen] + "…"
	}
	return s
}

func resultTag(result bool) string {
	if result {
		return "PASS"
	}
	return "FAIL"
}

// clauseExplanation generates a human-readable explanation from a ClauseNode's data.
func clauseExplanation(c *ClauseNode) string {
	if !c.ValueFromParam.IsZero() && c.ResolvedValue == nil {
		return fmt.Sprintf("value_from_param %q not found in params → FAIL", c.ValueFromParam.String())
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
	return fmt.Sprintf("%s %s %s → %s", formatValue(f.FieldValue), f.Op, f.OtherField.String(), tag)
}
