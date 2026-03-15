package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sufield/stave/internal/cli/ui"
	contexts "github.com/sufield/stave/internal/config"
)

// Edition defines the build flavor of the application.
type Edition string

const (
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
		return Environment{}
	}
	name, ctx, ok, resolveErr := st.ResolveSelected()
	if resolveErr == nil && ok && ctx != nil && ctx.Production {
		return Environment{
			IsProduction: true,
			Source:       fmt.Sprintf("context %q has production: true", name),
		}
	}

	return Environment{}
}

// ---------------------------------------------------------------------------
// Policy: Production Guard
// ---------------------------------------------------------------------------

// SafetyPolicy defines which commands are restricted in production.
type SafetyPolicy struct {
	BlockedCommands map[string]bool
}

// DefaultSafetyPolicy blocks commands that permanently destroy evidence.
var DefaultSafetyPolicy = SafetyPolicy{
	BlockedCommands: map[string]bool{
		"prune": true,
	},
}

// ProductionGuard prevents the developer binary from performing
// dangerous operations against production environments.
type ProductionGuard struct {
	Edition Edition
	Policy  SafetyPolicy
	Stderr  io.Writer
}

// Check evaluates whether a command is safe to run. Returns a UserError
// if the command is hard-blocked, or prints a warning for read-only dev
// commands running against production.
func (g *ProductionGuard) Check(cmdName string, env Environment) error {
	if g.Edition != EditionDev || !env.IsProduction {
		return nil
	}

	if g.Policy.BlockedCommands[cmdName] {
		return &ui.UserError{
			Err: fmt.Errorf(
				"command %q is blocked in production (%s): "+
					"use `stave snapshot archive` to move snapshots without deleting them, "+
					"or switch to a non-production context to prune",
				cmdName, env.Source),
		}
	}

	stderr := g.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	fmt.Fprintf(stderr,
		"WARNING: stave-dev running against production environment (%s).\n"+
			"Dev commands are restricted to read-only mode for safety.\n\n",
		env.Source)

	return nil
}

// ---------------------------------------------------------------------------
// Bootstrap integration
// ---------------------------------------------------------------------------

// checkDevProductionGuard detects the environment and runs the safety guard.
// Called from App.bootstrap before any command executes.
func (a *App) checkDevProductionGuard(cmd interface{ Name() string }) error {
	detector := &EnvironmentDetector{EnvProvider: os.Getenv}
	env := detector.Detect()

	guard := &ProductionGuard{
		Edition: a.Edition,
		Policy:  DefaultSafetyPolicy,
		Stderr:  a.Root.ErrOrStderr(),
	}

	return guard.Check(cmd.Name(), env)
}
