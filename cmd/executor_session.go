package cmd

import (
	"log/slog"

	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/cmd/enforce"
	"github.com/sufield/stave/internal/cli/ui"
)

func persistSessionStateIfApplicable(resolver *projctx.Resolver, args []string) string {
	if resolver == nil {
		return ""
	}
	projectRoot, err := resolver.DetectProjectRoot(resolver.WorkingDir)
	if err != nil {
		// Project root detection is allowed to fail (running outside
		// a project tree, missing .stave marker), but the failure is
		// otherwise invisible. Log at debug so a stuck "no workflow
		// handoff printed" report can be diagnosed without
		// re-instrumenting the call.
		slog.Debug("session persistence skipped", "error", err)
		return ""
	}
	// Best-effort: session state is advisory; failure doesn't affect
	// the command result. Log at debug — mirrors the
	// DetectProjectRoot pattern above — so a corrupted session file
	// surfaces in verbose output without forcing the operator to
	// re-instrument the call.
	if saveErr := projctx.SaveSession(projectRoot, args); saveErr != nil {
		slog.Debug("session save failed", "error", saveErr)
	}
	return projectRoot
}

func (a *App) printWorkflowHandoff(args []string, projectRoot string) {
	rt := ui.DefaultRuntime()
	rt.Quiet = a.Flags.Quiet
	rt.PrintWorkflowHandoff(ui.WorkflowHandoffRequest{
		Args:        args,
		ProjectRoot: projectRoot,
		NextCommand: enforce.NextCommandForProject,
	})
}
