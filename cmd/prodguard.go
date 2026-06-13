package cmd

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

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
		// production guard fell back to "non-production". The
		// previous shape silently treated every load failure as
		// "safe to run destructive commands" — fail-safe would be
		// IsProduction=true, but flipping the default risks
		// blocking every command in environments with transient
		// context-store errors. Logging keeps the gap visible while
		// preserving the established non-blocking behaviour.
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
// Policy: Production Guard
// ---------------------------------------------------------------------------

// SafetyPolicy defines which commands are restricted in production.
// The blocked list is mutated by governance config loading at bootstrap
// (SetBlockedCommands) and read by ProductionGuard.Check; the mutex
// serializes those accesses so a future caller that wires the guard
// outside the bootstrap PreRun lifecycle (e.g. tests, parallel command
// invocations sharing the package-level default) does not race on the
// underlying map header.
type SafetyPolicy struct {
	mu              sync.RWMutex
	blockedCommands map[string]struct{}
}

// IsBlocked reports whether cmdName is on the blocked list.
func (p *SafetyPolicy) IsBlocked(cmdName string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.blockedCommands[cmdName]
	return ok
}

// Set replaces the blocked-command list. Pass nil or empty to clear.
// Returns an error when any entry is empty after trimming — a
// silently-ignored empty entry is the symptom of a typo'd config
// that would otherwise leave production protection partially in
// place.
func (p *SafetyPolicy) Set(cmds []string) error {
	m := make(map[string]struct{}, len(cmds))
	for _, c := range cmds {
		trimmed := strings.TrimSpace(c)
		if trimmed == "" {
			return errors.New("SafetyPolicy.Set: blocked command name must not be empty / whitespace")
		}
		m[trimmed] = struct{}{}
	}
	p.mu.Lock()
	p.blockedCommands = m
	p.mu.Unlock()
	return nil
}

// DefaultSafetyPolicy blocks commands that permanently destroy evidence.
// Override with SetBlockedCommands to customize for your environment.
// Initialized via Set() rather than direct field assignment so the
// init path takes the same write lock as runtime updates — keeps a
// single canonical write sequence for the package-level default.
var DefaultSafetyPolicy = func() *SafetyPolicy {
	p := &SafetyPolicy{}
	if err := p.Set([]string{"prune"}); err != nil {
		// Static literal — the only way Set fails here is a code
		// edit that introduces an empty entry. Panic so the
		// regression is loud at process start rather than a
		// silently-disabled production guard.
		panic("prodguard: failed to seed DefaultSafetyPolicy: " + err.Error())
	}
	return p
}()

// SetBlockedCommands replaces the production guard blocked command list
// on the package-level default. Pass nil or empty to keep the default.
// Returns Set's validation error so a malformed config (empty entry,
// whitespace-only) surfaces at the call site rather than leaving the
// guard silently disabled.
func SetBlockedCommands(cmds []string) error {
	if len(cmds) == 0 {
		return nil
	}
	return DefaultSafetyPolicy.Set(cmds)
}

// ProductionGuard prevents the developer binary from performing
// dangerous operations against production environments.
type ProductionGuard struct {
	Edition Edition
	Policy  *SafetyPolicy
	Stderr  io.Writer
}

// Check evaluates whether a command is safe to run. Returns a UserError
// if the command is hard-blocked, or prints a warning for read-only dev
// commands running against production.
func (g *ProductionGuard) Check(cmdName string, env Environment) error {
	if g.Edition != EditionDev || !env.IsProduction {
		return nil
	}

	if g.Policy != nil && g.Policy.IsBlocked(cmdName) {
		// Generic message: the earlier shape hard-coded a
		// "stave snapshot archive" suggestion that only made
		// sense when the blocked command was prune. For any other
		// blocked command (reset, scrub, etc.) the suggestion was
		// misleading. Keep the actionable bit ("switch to a non-
		// production context") and let the operator find the
		// command-specific alternative themselves.
		return &ui.UserError{
			Err: fmt.Errorf(
				"command %q is blocked in production (%s): "+
					"switch to a non-production context to run it, "+
					"or use a read-only alternative if one exists",
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
