// Package controldata holds the embedded built-in control YAML files.
//
// The embedded/ directory is populated at build time by "make sync-controls",
// which copies canonical control definitions from the top-level controls/
// directory. The embed.FS is exported so that adapter and test packages can
// access the bundled controls without knowing the physical file layout.
package controldata

import "embed"

//go:embed embedded/s3/**/*.yaml
var FS embed.FS
