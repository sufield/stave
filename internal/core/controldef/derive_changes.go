package controldef

import (
	"fmt"

	"github.com/sufield/stave/internal/core/predicate"
)

// DeriveChanges converts misconfigurations into structured PropertyChange
// entries. Boolean inversions produce safe defaults; everything else is
// context-dependent.
func DeriveChanges(misconfigs []Misconfiguration) []PropertyChange {
	var changes []PropertyChange
	for i := range misconfigs {
		m := &misconfigs[i]
		if m.Property.IsZero() {
			continue
		}

		pc := PropertyChange{
			PropertyPath: m.Property.String(),
			CurrentValue: formatValue(m.ActualValue),
		}

		switch {
		case isBooleanInversion(m):
			pc.RequiredValue = invertBool(m.ActualValue)
			pc.HasSafeDefault = true
			pc.Description = fmt.Sprintf("Set %s to %s", m.DisplayProperty(), pc.RequiredValue)
		case m.Operator == predicate.OpMissing:
			pc.RequiredValue = "present"
			pc.HasSafeDefault = false
			pc.Description = fmt.Sprintf("Ensure %s is present", m.DisplayProperty())
		case m.Operator == predicate.OpPresent:
			pc.RequiredValue = "absent"
			pc.HasSafeDefault = false
			pc.Description = "Remove " + m.DisplayProperty()
		case m.Operator == predicate.OpNe:
			pc.RequiredValue = formatValue(m.UnsafeValue)
			pc.HasSafeDefault = false
			pc.Description = fmt.Sprintf("Set %s to %s", m.DisplayProperty(), pc.RequiredValue)
		default:
			pc.HasSafeDefault = false
			pc.Description = fmt.Sprintf("Change %s from %s", m.DisplayProperty(), pc.CurrentValue)
		}

		changes = append(changes, pc)
	}
	return changes
}

// ConfidenceFloat maps a confidence level string to a float64.
func ConfidenceFloat(level string) float64 {
	switch level {
	case "HIGH":
		return 1.0
	case "MEDIUM":
		return 0.7
	case "LOW":
		return 0.4
	default:
		return 0.5
	}
}

func isBooleanInversion(m *Misconfiguration) bool {
	if m.Operator != predicate.OpEq {
		return false
	}
	_, unsafeOK := m.UnsafeValue.(bool)
	_, actualOK := m.ActualValue.(bool)
	return unsafeOK && actualOK
}

func invertBool(v any) string {
	if b, ok := v.(bool); ok {
		if b {
			return "false"
		}
		return "true"
	}
	return ""
}

func formatValue(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}
