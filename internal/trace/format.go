package trace

import (
	"fmt"
	"unicode/utf8"

	"github.com/sufield/stave/internal/domain/predicate"
)

const (
	// maxDisplayLen caps formatted values to keep trace outputs readable.
	maxDisplayLen = 120

	tagPass = "PASS"
	tagFail = "FAIL"
)

// Explain generates a human-readable summary of the clause evaluation.
func (c *ClauseNode) Explain() string {
	if !c.ValueFromParam.IsZero() && c.ResolvedValue == nil {
		return fmt.Sprintf("parameter %s not found → %s", c.ValueFromParam, tagFail)
	}

	tag := resultTag(c.Result)

	if !c.FieldExists {
		switch c.Op {
		case predicate.OpMissing, predicate.OpPresent, predicate.OpListEmpty:
			return fmt.Sprintf("field %q is absent (checked %s %v) → %s",
				c.Field, c.Op, c.ResolvedValue, tag)
		case predicate.OpNe:
			return fmt.Sprintf("field %q is absent (absent != %v is true) → %s",
				c.Field, c.ResolvedValue, tag)
		default:
			return fmt.Sprintf("field %q is absent → %s", c.Field, tag)
		}
	}

	return fmt.Sprintf("%s %s %s → %s",
		formatValue(c.ActualValue), c.Op, formatValue(c.ResolvedValue), tag)
}

// Explain generates a human-readable summary of the field-to-field comparison.
func (f *FieldRefNode) Explain() string {
	tag := resultTag(f.Result)
	if !f.FieldExists {
		return fmt.Sprintf("field %q is absent → %s", f.Field, tag)
	}
	return fmt.Sprintf("%s %s %s → %s",
		formatValue(f.ActualValue), f.Op, f.OtherField, tag)
}

// formatValue produces a quoted string for strings, or a standard string
// representation for other types, truncated for readability.
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
	return truncate(s, maxDisplayLen)
}

func resultTag(result bool) string {
	if result {
		return tagPass
	}
	return tagFail
}

// truncate safely shortens a string to n runes, not bytes.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	var count int
	for i := range s {
		if count == n {
			return s[:i] + "…"
		}
		count++
	}
	return s
}
