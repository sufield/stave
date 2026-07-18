package risk

import (
	policy "github.com/sufield/stave/internal/core/controldef"
)

// Exploitability string constants matching evaluation.Exploitability*.
// Duplicated here to avoid an import cycle (evaluation imports risk).
const (
	exploitableStr = "exploitable"
	oneAwayStr     = "one_away"
)

// ElevatedSeverity computes the effective severity of a finding
// based on its base severity, chain exploitability, and chain
// complexity. Critical never downgrades; dependent complexity caps
// at high.
//
// The exploitability parameter accepts the string value from
// evaluation.Exploitability to avoid an import cycle.
func ElevatedSeverity(
	base policy.Severity,
	exploitability string,
	complexity policy.ChainComplexity,
) policy.Severity {
	if base == policy.SeverityCritical {
		return policy.SeverityCritical
	}

	switch exploitability {
	case exploitableStr:
		return elevateExploitable(base, complexity)
	case oneAwayStr:
		return elevateOneAway(base, complexity)
	default:
		return base
	}
}

func elevateExploitable(base policy.Severity, complexity policy.ChainComplexity) policy.Severity {
	switch complexity {
	case policy.ComplexityAutomated:
		if base.Gte(policy.SeverityMedium) {
			return policy.SeverityCritical
		}
		return policy.SeverityHigh
	case policy.ComplexityManual:
		if base == policy.SeverityHigh {
			return policy.SeverityCritical
		}
		if base == policy.SeverityMedium {
			return policy.SeverityHigh
		}
		return policy.SeverityMedium
	case policy.ComplexityDependent:
		if base == policy.SeverityHigh {
			return policy.SeverityHigh
		}
		if base == policy.SeverityMedium {
			return policy.SeverityHigh
		}
		return policy.SeverityMedium
	default:
		return base
	}
}

func elevateOneAway(base policy.Severity, complexity policy.ChainComplexity) policy.Severity {
	if complexity == policy.ComplexityAutomated && base == policy.SeverityMedium {
		return policy.SeverityHigh
	}
	return base
}
