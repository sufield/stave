package controldef

import (
	"fmt"

	"github.com/sufield/stave/internal/core/predicate"
)

// DeltaPath represents one independent fix path that eliminates a
// finding. For AND predicates each clause is an independent fix; for
// simple predicates there is one DeltaPath.
type DeltaPath struct {
	PropertyLabel string // human-readable from registry
	PropertyPath  string // raw observation path
	CurrentValue  string // what was observed
	FixAction     string // human-readable change needed
}

// DeriveDeltas converts misconfigurations into human-readable delta
// paths using the property-path registry from defect derivation.
// Returns nil when no delta can be produced (no misconfigurations or
// all paths lack labels).
func DeriveDeltas(misconfigs []Misconfiguration) []DeltaPath {
	if len(misconfigs) == 0 {
		return nil
	}
	var deltas []DeltaPath
	for i := range misconfigs {
		m := &misconfigs[i]
		if m.Property.IsZero() {
			continue
		}

		path := m.Property.TrimPrefix(propertiesPathPrefix)
		label := pathLabel(path)
		if label == "" {
			continue
		}

		if isKindGate(path, m.Operator) {
			continue
		}

		dp := DeltaPath{
			PropertyLabel: label,
			PropertyPath:  path,
			CurrentValue:  formatValue(m.ActualValue),
			FixAction:     fixAction(m),
		}
		deltas = append(deltas, dp)
	}
	if len(deltas) == 0 {
		return nil
	}
	return deltas
}

func fixAction(m *Misconfiguration) string {
	switch m.Operator {
	case predicate.OpEq:
		return eqFixAction(m.UnsafeValue, m.ActualValue)
	case predicate.OpNe:
		return fmt.Sprintf("set to %v", m.UnsafeValue)
	case predicate.OpGt:
		return fmt.Sprintf("reduce to %v or below", m.UnsafeValue)
	case predicate.OpLt:
		return fmt.Sprintf("increase to %v or above", m.UnsafeValue)
	case predicate.OpGte:
		return fmt.Sprintf("reduce below %v", m.UnsafeValue)
	case predicate.OpLte:
		return fmt.Sprintf("increase above %v", m.UnsafeValue)
	case predicate.OpMissing:
		return "populate this property in the configuration"
	case predicate.OpPresent:
		return "remove this property from the configuration"
	case predicate.OpContains:
		return fmt.Sprintf("remove %v from the list", m.UnsafeValue)
	case predicate.OpIn:
		return fmt.Sprintf("change to a value not in %v", m.UnsafeValue)
	default:
		return fmt.Sprintf("change from current value (%v)", formatValue(m.ActualValue))
	}
}

func eqFixAction(unsafeValue, actualValue any) string {
	switch v := unsafeValue.(type) {
	case bool:
		if v {
			return "set to false (disable)"
		}
		return "set to true (enable)"
	case string:
		return fmt.Sprintf("change from %q to any other value, or remove", v)
	default:
		return fmt.Sprintf("change from %v", actualValue)
	}
}
