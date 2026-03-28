package cmd

import (
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
		return ""
	}
	// Best-effort: session state is advisory; failure doesn't affect the command result.
	_ = projctx.SaveSession(projectRoot, args)
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
