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
	// Session state is advisory but its loss is user-visible: the
	// next command's workflow handoff hint won't fire without a
	// fresh session file. Log at warn (not debug) so a persistent
	// failure surfaces during normal operation rather than only
	// under -vv. project_root is included so the operator can
	// locate the offending state directory immediately.
	if saveErr := projctx.SaveSession(projectRoot, args); saveErr != nil {
		slog.Warn("session save failed", "error", saveErr, "project_root", projectRoot)
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
