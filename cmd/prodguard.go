package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	contexts "github.com/sufield/stave/internal/config"
)

// ProductionSource returns a human-readable description of why the
// environment is detected as production, or "" if it is not.
func ProductionSource() string {
	if strings.EqualFold(os.Getenv("STAVE_ENV"), "production") {
		return "STAVE_ENV=production"
	}
	st, _, err := contexts.Load()
	if err != nil {
		return ""
	}
	name, ctx, ok, resolveErr := st.ResolveSelected()
	if resolveErr != nil || !ok || ctx == nil {
		return ""
	}
	if ctx.Production {
		return fmt.Sprintf("context %q has production: true", name)
	}
	return ""
}

// destructiveDevCommands lists command paths that permanently modify or
// delete data and must never run against production environments.
var destructiveDevCommands = map[string]bool{
	"prune": true,
}

// checkDevProductionGuard warns or blocks when the dev binary targets a
// production environment. Read-only dev commands (trace, explain, lint)
// print a warning for break-glass debugging. Destructive dev commands
// (prune) are hard-blocked.
func (a *App) checkDevProductionGuard(cmd *cobra.Command) error {
	if a.Edition != "dev" {
		return nil
	}
	source := ProductionSource()
	if source == "" {
		return nil
	}

	cmdName := cmd.Name()

	// Hard block destructive commands
	if destructiveDevCommands[cmdName] {
		return &ui.UserError{
			Err: fmt.Errorf(
				"command %q is blocked in production (%s): "+
					"use `stave snapshot archive` to move snapshots without deleting them, "+
					"or unset STAVE_ENV / switch to a non-production context to prune",
				cmdName, source),
		}
	}

	// Warn on all other dev commands
	fmt.Fprintf(os.Stderr,
		"WARNING: stave-dev running against production environment (%s).\n"+
			"Dev commands are read-only in this mode. Use the production binary for operational workflows.\n\n",
		source)
	return nil
}
