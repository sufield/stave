package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	scopemanifest "github.com/sufield/stave/features"
)

// TestFeaturesScopeManifest_NoForbiddenCommands is the scope-drift lint.
//
// features/scope.yaml declares the capabilities Stave deliberately does
// not provide. Each entry may list `forbids` — CLI command names that
// would re-introduce that capability. This test fails the build if any
// forbidden name is registered anywhere in the command tree, so a
// regression (e.g. someone re-adds `collect` or `snapshot prune`) is
// caught in CI rather than in review.
//
// It enumerates the dev-edition tree, which is a superset of the
// standard tree, so dev-only commands are covered too.
func TestFeaturesScopeManifest_NoForbiddenCommands(t *testing.T) {
	registered := map[string]bool{}
	collectCommandNames(getDevRootCmd(), registered)

	entries, err := scopemanifest.OutOfScope()
	if err != nil {
		t.Fatalf("load scope manifest: %v", err)
	}

	for _, e := range entries {
		for _, name := range e.Forbids {
			if registered[name] {
				t.Errorf("command %q is registered but re-introduces out-of-scope capability %q (%s).\n"+
					"Either remove the command, or if the capability is now intentionally in scope, "+
					"delete the %q entry from features/scope.yaml.",
					name, e.ID, e.Label, e.ID)
			}
		}
	}
}

// collectCommandNames records the first token of every command's Use
// string (the command name) across the whole tree.
func collectCommandNames(cmd *cobra.Command, out map[string]bool) {
	if name := strings.Fields(cmd.Use); len(name) > 0 {
		out[name[0]] = true
	}
	for _, sub := range cmd.Commands() {
		collectCommandNames(sub, out)
	}
}
