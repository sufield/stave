package risk

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestPriorityScore_DimensionOrdering(t *testing.T) {
	tests := []struct {
		name    string
		a, b    PriorityInput
		aHigher bool
	}{
		{
			name: "automated scores higher than dependent at same severity",
			a: PriorityInput{
				Severity:   policy.SeverityCritical,
				Complexity: policy.ComplexityAutomated,
			},
			b: PriorityInput{
				Severity:   policy.SeverityCritical,
				Complexity: policy.ComplexityDependent,
			},
			aHigher: true,
		},
		{
			name: "prod scores higher than dev",
			a: PriorityInput{
				Severity:        policy.SeverityHigh,
				EnvironmentTier: TierProduction,
			},
			b: PriorityInput{
				Severity:        policy.SeverityHigh,
				EnvironmentTier: TierDev,
			},
			aHigher: true,
		},
		{
			name: "choke point with 7 shared chains scores higher",
			a: PriorityInput{
				Severity:         policy.SeverityHigh,
				SharedChainCount: 7,
			},
			b: PriorityInput{
				Severity:         policy.SeverityHigh,
				SharedChainCount: 0,
			},
			aHigher: true,
		},
		{
			name: "incident precedent adds bonus",
			a: PriorityInput{
				Severity:             policy.SeverityMedium,
				HasIncidentPrecedent: true,
			},
			b: PriorityInput{
				Severity:             policy.SeverityMedium,
				HasIncidentPrecedent: false,
			},
			aHigher: true,
		},
		{
			name: "deterministic same inputs same score",
			a: PriorityInput{
				Severity:         policy.SeverityHigh,
				Complexity:       policy.ComplexityManual,
				EnvironmentTier:  TierProduction,
				SharedChainCount: 3,
			},
			b: PriorityInput{
				Severity:         policy.SeverityHigh,
				Complexity:       policy.ComplexityManual,
				EnvironmentTier:  TierProduction,
				SharedChainCount: 3,
			},
			aHigher: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scoreA := PriorityScore(tt.a)
			scoreB := PriorityScore(tt.b)
			if tt.aHigher && scoreA <= scoreB {
				t.Errorf("expected A (%f) > B (%f)", scoreA, scoreB)
			}
			if !tt.aHigher && scoreA != scoreB {
				t.Errorf("expected A (%f) == B (%f)", scoreA, scoreB)
			}
		})
	}
}

func TestPriorityScore_BonusesCantFlipSeverity(t *testing.T) {
	// HAZOP deviation 2: at the same complexity and environment tier,
	// choke-point and precedent bonuses must never let LOW outrank CRITICAL.
	tiers := []EnvironmentTier{TierDev, TierStaging, TierProduction, TierCritical}
	complexities := []policy.ChainComplexity{
		policy.ComplexityAutomated, policy.ComplexityManual, policy.ComplexityDependent,
	}
	for _, tier := range tiers {
		for _, cx := range complexities {
			low := PriorityScore(PriorityInput{
				Severity:             policy.SeverityLow,
				Complexity:           cx,
				EnvironmentTier:      tier,
				SharedChainCount:     100,
				HasIncidentPrecedent: true,
			})
			critical := PriorityScore(PriorityInput{
				Severity:        policy.SeverityCritical,
				Complexity:      cx,
				EnvironmentTier: tier,
			})
			if low >= critical {
				t.Errorf("tier=%d cx=%s: LOW maxed (%f) outranks CRITICAL bare (%f)",
					tier, cx, low, critical)
			}
		}
	}
}

func TestPrioritizeFindings_SortOrder(t *testing.T) {
	chains := map[kernel.ChainID]*policy.ChainDefinition{
		"chain_auto": {
			ID:          "chain_auto",
			Complexity:  policy.ComplexityAutomated,
			Description: "Capital One 2019 — role assumption through SSRF to metadata service gives attacker IAM credentials",
		},
		"chain_dep": {
			ID:         "chain_dep",
			Complexity: policy.ComplexityDependent,
		},
	}

	cfs := []findings.CompoundFinding{
		{
			ChainID:         "chain_dep",
			Severity:        policy.SeverityCritical,
			ControlsFailing: []kernel.ControlID{"CTL.A"},
		},
		{
			ChainID:         "chain_auto",
			Severity:        policy.SeverityCritical,
			ControlsFailing: []kernel.ControlID{"CTL.A", "CTL.B"},
		},
	}

	result := PrioritizeFindings(cfs, chains, TierProduction)
	if len(result) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result))
	}
	if result[0].Finding.ChainID != "chain_auto" {
		t.Errorf("expected chain_auto first (automated + incident), got %s", result[0].Finding.ChainID)
	}
	if result[0].Priority <= result[1].Priority {
		t.Errorf("first should have higher priority: %f vs %f", result[0].Priority, result[1].Priority)
	}
}
