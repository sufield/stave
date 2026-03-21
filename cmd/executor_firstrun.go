package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/state"
)

// prepareFirstRunHint uses os.Stderr directly because it runs before
// the Cobra command tree is initialized — no cmd.ErrOrStderr() is available.
func prepareFirstRunHint(args []string) (bool, string) {
	if ui.ShouldSkipFirstRunHint(args) {
		return false, ""
	}
	markerPath, err := state.FirstRunMarkerPath()
	if err != nil {
		return false, ""
	}
	if _, statErr := os.Stat(markerPath); os.IsNotExist(statErr) {
		fmt.Fprintln(os.Stderr, ui.FirstRunHintMessage)
		return true, markerPath
	}
	return false, markerPath
}

func ensureFirstRunRunHint(message string, args []string) string {
	if strings.Contains(message, "\nRun:") {
		return message
	}
	if len(args) == 0 {
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
		// Best-effort: failure to persist the marker is harmless; the hint just shows again.
		_ = state.MarkFirstRunSeen(markerPath)
	}
}

func (a *App) printNoProjectHintIfNeeded(args []string) {
	if len(args) != 0 {
		return
	}
	if _, found := projconfig.FindNearestFile(appconfig.ProjectConfigFile); !found {
		fmt.Fprintf(a.Root.ErrOrStderr(), "No Stave project found in this directory tree. Run `%s` to create one.\n", cliCommand("init"))
	}
}
