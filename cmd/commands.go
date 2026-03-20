package cmd

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/apply"
	applyvalidate "github.com/sufield/stave/cmd/apply/validate"
	applyverify "github.com/sufield/stave/cmd/apply/verify"
	"github.com/sufield/stave/cmd/bugreport"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/diagnose"
	"github.com/sufield/stave/cmd/diagnose/artifacts"
	diagdocs "github.com/sufield/stave/cmd/diagnose/docs"
	diagreport "github.com/sufield/stave/cmd/diagnose/report"
	"github.com/sufield/stave/cmd/doctor"
	"github.com/sufield/stave/cmd/enforce"
	"github.com/sufield/stave/cmd/initcmd"
	initalias "github.com/sufield/stave/cmd/initcmd/alias"
	initconfig "github.com/sufield/stave/cmd/initcmd/config"
	"github.com/sufield/stave/cmd/inspect"
	"github.com/sufield/stave/cmd/prune"
	"github.com/sufield/stave/internal/cli/ui"
)

const (
	groupGettingStarted = "getting-started"
	groupCore           = "core-evaluation"
	groupWorkflow       = "workflow"
	groupArtifacts      = "artifacts"
	groupSettings       = "settings"
	groupIntrospection  = "introspection"
	groupDevTools       = "dev-tools"
)

// WireProdCommands attaches the full command tree to the root command.
// All commands are production-ready. The dev binary (stave-dev) adds
// edition metadata via WithDevCommands but no additional commands.
func WireProdCommands(app *App) {
	root := app.Root
	p := app.Provider

	// Getting started
	root.AddCommand(initcmd.NewInitCmd())
	root.AddCommand(initcmd.NewGenerateCmd())

	// Control Engine
	root.AddCommand(applyvalidate.NewCmd(p, ui.DefaultRuntime()))
	root.AddCommand(apply.NewApplyCmd(p))
	root.AddCommand(applyverify.NewCmd(p, ui.DefaultRuntime()))
	root.AddCommand(diagnose.NewDiagnoseCmd(p))
	root.AddCommand(diagnose.NewExplainCmd(p))
	root.AddCommand(diagnose.NewTraceCmd(p))
	root.AddCommand(diagnose.NewPromptCmd(p))

	// Workflow & CI
	root.AddCommand(enforce.NewStatusCmd())

	snapshotCmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Snapshot lifecycle commands",
		Long:  "Grouped snapshot lifecycle commands: cleanup, archive, upcoming, quality, plan, hygiene, diff, manifest." + OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}
	root.AddCommand(snapshotCmd)
	wireSnapshotSubtree(snapshotCmd, p)

	ciCmd := &cobra.Command{
		Use:   "ci",
		Short: "CI/CD policy and baseline commands",
		Long:  "Grouped CI/CD commands: baseline, gate, fix-loop, diff, fix." + OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}
	root.AddCommand(ciCmd)
	wireCISubtree(ciCmd, p)

	// Data & Artifacts
	root.AddCommand(enforce.NewGenerateCmd())
	root.AddCommand(diagreport.NewReportCmd())
	root.AddCommand(artifacts.NewLintCmd())
	root.AddCommand(artifacts.NewFmtCmd())
	root.AddCommand(artifacts.NewControlsCmd(p))
	root.AddCommand(artifacts.NewPacksCmd())

	// Introspection
	root.AddCommand(inspect.NewInspectCmd())

	// Supportability
	root.AddCommand(doctor.NewCmd())
	root.AddCommand(bugreport.NewCmd())
	root.AddCommand(enforce.NewGraphCmd(p))
	root.AddCommand(initalias.NewCmd(root))
	root.AddCommand(newCapabilitiesCmd())
	root.AddCommand(newSchemasCmd())
	root.AddCommand(newVersionCmd(app.Edition))

	// Documentation
	docsCmd := &cobra.Command{
		Use:   "docs",
		Short: "Documentation workflow commands",
		Long:  "Grouped docs commands: search, open." + OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}
	docsCmd.AddCommand(diagdocs.NewDocsSearchCmd(), diagdocs.NewDocsOpenCmd())
	root.AddCommand(docsCmd)

	// Settings
	root.AddCommand(initconfig.NewConfigCmd(ui.DefaultRuntime()))
}

func wireSnapshotSubtree(snapshotCmd *cobra.Command, p *compose.Provider) {
	snapshotCmd.AddCommand(enforce.NewDiffCmd(p))
	for _, subCmd := range prune.Commands(p) {
		snapshotCmd.AddCommand(subCmd)
	}
	for _, subCmd := range prune.DevCommands(p) {
		snapshotCmd.AddCommand(subCmd)
	}
}

func wireCISubtree(ciCmd *cobra.Command, p *compose.Provider) {
	ciCmd.AddCommand(enforce.NewBaselineCmd())
	ciCmd.AddCommand(enforce.NewGateCmd(p))
	ciCmd.AddCommand(enforce.NewFixLoopCmd(p))
	ciCmd.AddCommand(enforce.NewCiDiffCmd())
	ciCmd.AddCommand(enforce.NewFixCmd(p))
}

func assignCommandGroup(root *cobra.Command, use, groupID string) {
	cmd, _, err := root.Find([]string{use})
	if err != nil || cmd == nil {
		return
	}
	cmd.GroupID = groupID
}
