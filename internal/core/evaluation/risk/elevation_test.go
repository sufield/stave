package risk

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestElevatedSeverity(t *testing.T) {
	tests := []struct {
		name           string
		base           policy.Severity
		exploitability string
		complexity     policy.ChainComplexity
		want           policy.Severity
	}{
		// Critical never downgrades
		{"critical-exploitable-automated", policy.SeverityCritical, "exploitable", policy.ComplexityAutomated, policy.SeverityCritical},
		{"critical-reachable", policy.SeverityCritical, "reachable", policy.ComplexityManual, policy.SeverityCritical},

		// Standalone (reachable): no change
		{"low-standalone", policy.SeverityLow, "reachable", "", policy.SeverityLow},
		{"medium-standalone", policy.SeverityMedium, "reachable", "", policy.SeverityMedium},
		{"high-standalone", policy.SeverityHigh, "reachable", "", policy.SeverityHigh},

		// One-away: only automated+medium elevates
		{"low-oneaway-automated", policy.SeverityLow, "one_away", policy.ComplexityAutomated, policy.SeverityLow},
		{"medium-oneaway-automated", policy.SeverityMedium, "one_away", policy.ComplexityAutomated, policy.SeverityHigh},
		{"medium-oneaway-manual", policy.SeverityMedium, "one_away", policy.ComplexityManual, policy.SeverityMedium},
		{"medium-oneaway-dependent", policy.SeverityMedium, "one_away", policy.ComplexityDependent, policy.SeverityMedium},
		{"high-oneaway-automated", policy.SeverityHigh, "one_away", policy.ComplexityAutomated, policy.SeverityHigh},

		// Exploitable + automated
		{"low-exploitable-automated", policy.SeverityLow, "exploitable", policy.ComplexityAutomated, policy.SeverityHigh},
		{"medium-exploitable-automated", policy.SeverityMedium, "exploitable", policy.ComplexityAutomated, policy.SeverityCritical},
		{"high-exploitable-automated", policy.SeverityHigh, "exploitable", policy.ComplexityAutomated, policy.SeverityCritical},

		// Exploitable + manual
		{"low-exploitable-manual", policy.SeverityLow, "exploitable", policy.ComplexityManual, policy.SeverityMedium},
		{"medium-exploitable-manual", policy.SeverityMedium, "exploitable", policy.ComplexityManual, policy.SeverityHigh},
		{"high-exploitable-manual", policy.SeverityHigh, "exploitable", policy.ComplexityManual, policy.SeverityCritical},

		// Exploitable + dependent (caps at high)
		{"low-exploitable-dependent", policy.SeverityLow, "exploitable", policy.ComplexityDependent, policy.SeverityMedium},
		{"medium-exploitable-dependent", policy.SeverityMedium, "exploitable", policy.ComplexityDependent, policy.SeverityHigh},
		{"high-exploitable-dependent", policy.SeverityHigh, "exploitable", policy.ComplexityDependent, policy.SeverityHigh},

		// No complexity set: no elevation
		{"medium-exploitable-none", policy.SeverityMedium, "exploitable", "", policy.SeverityMedium},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ElevatedSeverity(tt.base, tt.exploitability, tt.complexity)
			if got != tt.want {
				t.Errorf("ElevatedSeverity(%s, %s, %s) = %s, want %s",
					tt.base, tt.exploitability, tt.complexity, got, tt.want)
			}
		})
	}
}
