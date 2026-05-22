package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/env"
	"github.com/sufield/stave/internal/platform/state"
)

// prepareFirstRunHint uses os.Stderr directly because it runs before
// the Cobra command tree is initialized — no cmd.ErrOrStderr() is available.
func prepareFirstRunHint(args []string) (bool, string) {
	if ui.ShouldSkipFirstRunHint(args) || env.Demo.IsTrue() {
		return false, ""
	}
	markerPath, err := state.FirstRunMarkerPath()
	if err != nil {
		return false, ""
	}
	_, statErr := os.Stat(markerPath)
	switch {
	case statErr == nil:
		// Marker present — operator has already seen the hint.
		return false, markerPath
	case os.IsNotExist(statErr):
		// Marker absent — first run; emit the hint and signal the
		// caller to write the marker after a successful command.
		fmt.Fprintln(os.Stderr, ui.FirstRunHintMessage)
		return true, markerPath
	default:
		// Some other error (permission denied, I/O failure). Surface
		// it via slog rather than silently treating it as "first run"
		// — emitting the hint on every invocation would be the wrong
		// signal, and silently suppressing reveals nothing about the
		// underlying access problem.
		slog.Warn("first-run marker stat failed; suppressing hint",
			"path", markerPath, "error", statErr)
		return false, ""
	}
}

func ensureFirstRunRunHint(message string, args []string) string {
	if len(args) == 0 || strings.Contains(message, "\nRun:") {
		return message
	}
	switch args[0] {
	case "init", "status":
		return fmt.Sprintf("%s\nRun: %s --help", message, cliCommand(args[0]))
	default:
		return message
	}
}

func markFirstRunHintSeenIfNeeded(show bool, markerPath string) {
	if show && markerPath != "" {
		// Best-effort: failure to persist the marker is harmless;
		// the hint just shows again on the next invocation. Log
		// at debug so a stuck "the hint never goes away" report
		// can be diagnosed without re-instrumenting the call.
		// Mirrors the slog handling for adjacent state failures
		// in this file.
		if err := state.MarkFirstRunSeen(markerPath); err != nil {
			slog.Debug("first-run marker persistence failed", "path", markerPath, "error", err)
		}
	}
}

func (a *App) printNoProjectHintIfNeeded(args []string) {
	// `args` is os.Args[1:], so args[0] (when present) is the
	// subcommand name. The earlier shape returned for ANY args !=
	// 0 — meaning the hint only fired when the user typed bare
	// `stave`, which is the one case where they DON'T need it
	// (the help screen explains how to start). Invert: skip when
	// no subcommand was given OR when the subcommand creates a
	// project (init, generate). Every other subcommand that
	// requires a project triggers the hint when no project is
	// found.
	if len(args) == 0 {
		return
	}
	subcommand := strings.TrimSpace(args[0])
	if subcommand == "" || strings.HasPrefix(subcommand, "-") {
		// Bare flag like `stave --help` — no subcommand to run.
		return
	}
	switch subcommand {
	case "init", "generate", "completion", "help", "version", "features":
		// Subcommands that DO NOT require an existing project; the
		// hint would mis-direct the user mid-init.
		return
	}
	_, found, err := projconfig.FindNearestFile(appconfig.AuditPolicyFile)
	switch {
	case err != nil:
		// Real lookup failure (cwd/home unavailable, permission
		// denied on a parent directory). Don't print the
		// "no project" hint — that would mislead the operator
		// into thinking the working tree is empty when the actual
		// issue is access. Surface the real cause via slog so it
		// shows up in -v / log-file mode.
		slog.Warn("project-file lookup failed; suppressing no-project hint",
			"file", appconfig.AuditPolicyFile, "error", err)
	case !found:
		// Legitimate no-project state — emit the suggestion.
		fmt.Fprintf(a.Root.ErrOrStderr(), "No Stave project found in this directory tree. Run `%s` to create one.\n", cliCommand("init"))
	}
}
