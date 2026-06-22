package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	contexts "github.com/sufield/stave/internal/config"
)

// Edition defines the build flavor of the application.
type Edition string

// Build edition constants.
const (
	// EditionProd constants.
	EditionProd Edition = "production"
	EditionDev  Edition = "dev"
)

// Environment captures the detected state of the runtime environment.
type Environment struct {
	IsProduction bool
	Source       string // e.g., "STAVE_ENV=production" or "context \"prod\" has production: true"
}

// ---------------------------------------------------------------------------
// Infrastructure: Environment Detector
// ---------------------------------------------------------------------------

// EnvironmentDetector identifies the current deployment context by checking
// environment variables and the active project context.
type EnvironmentDetector struct {
	EnvProvider func(string) string // defaults to os.Getenv
}

// Detect checks STAVE_ENV and the active context to determine whether
// the tool is operating against production resources.
func (d *EnvironmentDetector) Detect() Environment {
	getenv := d.EnvProvider
	if getenv == nil {
		getenv = os.Getenv
	}

	if strings.EqualFold(getenv("STAVE_ENV"), "production") {
		return Environment{IsProduction: true, Source: "STAVE_ENV=production"}
	}

	st, _, err := contexts.Load()
	if err != nil {
		// Surface the load failure so an operator can see why the
		// production guard fell back to "non-production". Logging keeps
		// the gap visible while preserving the non-blocking behaviour
		// (a transient context-store error should not block every
		// command).
		slog.Warn("production guard: failed to load context, assuming non-production", "error", err)
		return Environment{}
	}
	name, ctx, ok, resolveErr := st.ResolveSelected()
	if resolveErr == nil && ok && ctx != nil && ctx.IsProduction() {
		return Environment{
			IsProduction: true,
			Source:       fmt.Sprintf("context %q has production: true", name),
		}
	}

	return Environment{}
}

// ---------------------------------------------------------------------------
// Production guard: keep developer-only commands out of production
// ---------------------------------------------------------------------------
//
// Stave has no destructive commands — it reads snapshots and writes findings.
// The guard exists only to stop *developer-workflow* commands (project
// scaffolding, control authoring) from running against a production
// environment, where they have no purpose. Such commands are tagged with
// cmdutil.AnnotationDevOnly on the command (or a parent); the check walks the
// command's ancestry so a tag on `forge` / `generate` covers every subcommand.

// checkDevProductionGuard rejects a development-only command when a production
// environment is detected. Called from App.bootstrap before any command runs.
func (a *App) checkDevProductionGuard(cmd *cobra.Command) error {
	if !isDevOnlyCommand(cmd) {
		return nil
	}

	env := (&EnvironmentDetector{EnvProvider: os.Getenv}).Detect()
	if !env.IsProduction {
		return nil
	}

	return &ui.UserError{
		Err: fmt.Errorf(
			"command %q is development-only and cannot run in production (%s): "+
				"scaffolding and control authoring belong in development",
			cmd.Name(), env.Source),
	}
}

// isDevOnlyCommand reports whether cmd or any of its ancestors is tagged with
// cmdutil.AnnotationDevOnly, so tagging a parent command (forge, generate)
// protects its whole subtree.
func isDevOnlyCommand(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Annotations[cmdutil.AnnotationDevOnly] == "true" {
			return true
		}
	}
	return false
}
