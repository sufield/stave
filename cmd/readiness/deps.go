// Package readiness implements the 'stave readiness' command —
// a pre-evaluation report describing what Stave's catalog CAN'T
// detect against a given observation snapshot due to missing
// collector domains. Distinct from `stave apply --dry-run`,
// which checks input schema validity; readiness measures
// catalog effectiveness against the observed asset surface.
package readiness

import "github.com/sufield/stave/cmd/cmdutil/compose"

// Deps holds the adapter factories the readiness command needs:
// controls, chains, and observations. No CEL evaluator — the
// readiness analyzer does not invoke the evaluation engine.
type Deps struct {
	NewCtlRepo     compose.CtlRepoFactory
	NewChainLoader compose.ChainLoaderFactory
	NewObsRepo     compose.ObsRepoFactory
}
