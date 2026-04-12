// Package risk implements the three-layer risk scoring engine.
//
// Layer 1: Environmental — base_impact × asset_sensitivity × exposure_vector
// Layer 2: Compound — environmental × chain_escalation × blast_multiplier
// Layer 3: Resource — MAX(all compound scores) with breach probability annotation
package risk

// Environmental computes the per-finding environmental risk score.
// baseImpact is 0-100 from the control definition.
// sensitivity is the asset classification multiplier (phi=3.0, production=2.0, etc).
// exposure is the network reachability multiplier (public=2.0, vpc=1.0, etc).
func Environmental(baseImpact int, sensitivity, exposure float64) float64 {
	return float64(baseImpact) * sensitivity * exposure
}

// Compound computes the chain-escalated risk score.
// envScore is the environmental score from the highest-impact finding in the chain.
// chainEscalation is the co-failure multiplier (2 controls=1.8x, 3+=2.5x).
// blastMultiplier is the blast radius effect (detection controls=2.5+).
func Compound(envScore, chainEscalation, blastMultiplier float64) float64 {
	return envScore * chainEscalation * blastMultiplier
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
		return 1.8
	default:
		return 2.5
	}
}

// AssetSensitivity maps data classification tags to multipliers.
var AssetSensitivity = map[string]float64{
	"phi":        3.0,
	"cde":        3.0,
	"production": 2.0,
	"internal":   1.0,
	"dev":        0.5,
	"sandbox":    0.5,
}

// ExposureVector maps network reachability to multipliers.
var ExposureVector = map[string]float64{
	"public_internet": 2.0,
	"cross_account":   1.5,
	"vpc_internal":    1.0,
	"no_network":      0.5,
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
