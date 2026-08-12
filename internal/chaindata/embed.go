// Package chaindata holds the embedded built-in chain YAML files.
//
// The embedded/ directory is populated at build time by "make sync-chains",
// which copies canonical chain definitions from internal/chains/.
package chaindata

import "embed"

//go:embed embedded/*.yaml
var FS embed.FS
