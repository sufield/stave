// Package risk implements the three-layer risk scoring engine.
//
// Layer 1: Environmental — base_impact × asset_sensitivity × exposure_vector
// Layer 2: Compound — environmental × chain_escalation × blast_multiplier
// Layer 3: Resource — MAX(all compound scores) with breach probability annotation
package risk

const (
	// chainEscalation2 is the multiplier when 2 controls co-fail.
	// Two co-failing controls (e.g. public + unencrypted) are worse
	// than either alone, but not double — the attacker still needs
	// the same entry point.
	chainEscalation2 = 1.8

	// chainEscalationMax caps the multiplier for 3+ co-failing controls.
	// Bounded to reflect that stacking failures is catastrophic but
	// not infinitely multiplicative.
	chainEscalationMax = 2.5

	// crossAccountMultiplier increases risk score for cross-account
	// exposure — blast radius spans multiple AWS accounts, making
	// containment harder and detection more fragmented.
	crossAccountMultiplier = 1.5

	// publicInternetMultiplier increases risk when an asset is
	// directly reachable from the internet — any attacker can reach it.
	publicInternetMultiplier = 2.0

	// noNetworkMultiplier reduces risk for assets with no network
	// exposure — exploitation requires pre-existing access.
	noNetworkMultiplier = 0.5

	// phiSensitivity is the multiplier for Protected Health Information.
	// HIPAA breach penalties drive the highest sensitivity classification.
	phiSensitivity = 3.0

	// cdeSensitivity is the multiplier for Cardholder Data Environment.
	// PCI DSS breach penalties match PHI severity.
	cdeSensitivity = 3.0

	// productionSensitivity is the multiplier for production workloads.
	productionSensitivity = 2.0

	// devSensitivity reduces risk for development environments.
	devSensitivity = 0.5
)

// Environmental computes the per-finding environmental risk score.
// baseImpact is 0-100 from the control definition.
// sensitivity is the asset classification multiplier (phi=3.0, production=2.0, etc).
// exposure is the network reachability multiplier (public=2.0, vpc=1.0, etc).
//
// Capped at ScoreCatastrophic so a high-impact PHI bucket on the
// public internet (100 × 3 × 2 = 600 raw) does not dominate the
// scoring frame and crowd out every other finding when the report
// renders side-by-side bars.
func Environmental(baseImpact int, sensitivity, exposure float64) float64 {
	return min(float64(baseImpact)*sensitivity*exposure, float64(ScoreCatastrophic))
}

// Compound computes the chain-escalated risk score.
// envScore is the environmental score from the highest-impact finding in the chain.
// chainEscalation is the co-failure multiplier (2 controls=1.8x, 3+=2.5x).
// blastMultiplier is the blast radius effect (detection controls=2.5+).
//
// Capped at ScoreCatastrophic for the same display-frame reason as
// Environmental — uncapped scores from a 100-impact finding × 2.5
// chain × 2.5 blast = 625 are formally meaningless once a single
// finding already exceeds the catastrophic threshold.
func Compound(envScore, chainEscalation, blastMultiplier float64) float64 {
	return min(envScore*chainEscalation*blastMultiplier, float64(ScoreCatastrophic))
}

// ChainEscalation returns the multiplier for N co-failing controls.
// Intentionally not purely multiplicative — bounded to reflect that
// a bucket that's public + unencrypted + unlogged is catastrophically
// worse than public alone, but not infinitely worse.
//
//	1 control:  1.0x (no escalation)
//	2 controls: 1.8x
//	3+ controls: 2.5x (asymptote)
func ChainEscalation(failingCount int) float64 {
	switch {
	case failingCount <= 1:
		return 1.0
	case failingCount == 2:
		return chainEscalation2
	default:
		return chainEscalationMax
	}
}

// AssetSensitivity maps data classification tags to multipliers.
var AssetSensitivity = map[string]float64{
	"phi":        phiSensitivity,
	"cde":        cdeSensitivity,
	"production": productionSensitivity,
	"internal":   1.0,
	"dev":        devSensitivity,
	"sandbox":    devSensitivity,
}

// ExposureVector maps network reachability to multipliers.
var ExposureVector = map[string]float64{
	"public_internet": publicInternetMultiplier,
	"cross_account":   crossAccountMultiplier,
	"vpc_internal":    1.0,
	"no_network":      noNetworkMultiplier,
}

// LookupSensitivity returns the sensitivity multiplier for a classification.
// Returns 1.0 for unknown classifications.
func LookupSensitivity(classification string) float64 {
	if v, ok := AssetSensitivity[classification]; ok {
		return v
	}
	return 1.0
}

// LookupExposure returns the exposure multiplier for a vector.
// Returns 1.0 for unknown vectors.
func LookupExposure(vector string) float64 {
	if v, ok := ExposureVector[vector]; ok {
		return v
	}
	return 1.0
}
