package risk

// EnvironmentTier classifies the target environment of chain
// postcondition resources. Higher tiers receive higher severity
// multipliers.
type EnvironmentTier int

const (
	TierUnknown EnvironmentTier = iota
	TierDev
	TierStaging
	TierProduction
	TierCritical // production + PII/financial/regulated
)

// EnvironmentMultiplier returns a severity multiplier based on the
// target environment tier. Applied after the elevation matrix.
//
//	Unknown    → 1.0  (no change — graceful degradation)
//	Dev        → 0.5
//	Staging    → 0.75
//	Production → 1.0
//	Critical   → 2.0
func EnvironmentMultiplier(tier EnvironmentTier) float64 {
	switch tier {
	case TierDev:
		return 0.5
	case TierStaging:
		return 0.75
	case TierProduction:
		return 1.0
	case TierCritical:
		return 2.0
	default:
		return 1.0
	}
}

// ParseEnvironmentTier resolves a tier from common tag values.
// Returns TierUnknown for unrecognized values.
func ParseEnvironmentTier(value string) EnvironmentTier {
	switch value {
	case "dev", "development", "sandbox":
		return TierDev
	case "staging", "stage", "qa", "uat":
		return TierStaging
	case "prod", "production":
		return TierProduction
	case "critical", "pci", "hipaa", "pii", "financial":
		return TierCritical
	default:
		return TierUnknown
	}
}
