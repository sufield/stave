package stave

import (
	"fmt"

	"github.com/sufield/stave/internal/adapters/controls/yaml"
	appscore "github.com/sufield/stave/internal/app/score"
	"github.com/sufield/stave/internal/core/capabilities"
)

// ChainBudget summarises the chain-catalog budget the scorer needs
// to weight the chain-component score correctly. The two numbers
// are computed together from the same chain definition load so
// callers don't pay for two passes.
//
// ChainDefs is the total number of chain definitions in the catalog;
// MaxWeight is the severity-weighted sum across them, used as the
// denominator for "what fraction of the chain-risk catalog fired
// on this evaluation."
type ChainBudget struct {
	ChainDefs int
	MaxWeight float64
}

// BuiltinChainBudget loads the chain catalog from the conventional
// `chains/` directory (matching the CLI's default search) using the
// builtin capability registry, then reports the count and
// severity-weighted total. Wraps the LoadChains adapter so callers
// in cmd/ don't need to import the YAML adapter or the capabilities
// registry directly.
//
// Returns a zero-value ChainBudget with non-nil error if the
// chains directory exists but fails to parse. Missing chains
// directory returns (zero budget, nil error) — same fail-soft
// behaviour the underlying LoadChains has, since "no chains
// authored" is a valid project state.
func BuiltinChainBudget() (ChainBudget, error) {
	chains, err := yaml.LoadChains("chains", capabilities.Builtin())
	if err != nil {
		return ChainBudget{}, fmt.Errorf("load chain definitions: %w", err)
	}
	return ChainBudget{
		ChainDefs: len(chains),
		MaxWeight: appscore.ChainMaxWeight(chains),
	}, nil
}
