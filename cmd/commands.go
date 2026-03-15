package cmd

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/apply"
	applyvalidate "github.com/sufield/stave/cmd/apply/validate"
	applyverify "github.com/sufield/stave/cmd/apply/verify"
	"github.com/sufield/stave/cmd/diagnose"
	diagreport "github.com/sufield/stave/cmd/diagnose/report"
	"github.com/sufield/stave/cmd/enforce"
	"github.com/sufield/stave/cmd/ingest"
	"github.com/sufield/stave/cmd/initcmd"
	initconfig "github.com/sufield/stave/cmd/initcmd/config"
	"github.com/sufield/stave/cmd/prune"
	"github.com/sufield/stave/internal/cli/ui"
)

const (
	groupGettingStarted = "getting-started"
	groupCore           = "core-evaluation"
	groupWorkflow       = "workflow"
	groupArtifacts      = "artifacts"
	groupSettings       = "settings"
)

// WireProdCommands attaches the production command tree to the root command.
// Dev-only commands (doctor, bug-report, extractor, controls, packs, graph,
// lint, fmt, trace, prompt, docs, alias, schemas, capabilities, version
// subcommand, security-audit) are wired separately by WireDevCommands.
func WireProdCommands(app *App) {
	root := app.Root

	// Getting started
	root.AddCommand(initcmd.NewInitCmd())
	root.AddCommand(initcmd.NewGenerateCmd())

	// Control Engine
	root.AddCommand(applyvalidate.NewCmd(ui.DefaultRuntime()))
	root.AddCommand(apply.NewApplyCmd())
	root.AddCommand(applyverify.NewCmd(ui.DefaultRuntime()))
	root.AddCommand(diagnose.NewDiagnoseCmd())
	root.AddCommand(diagnose.NewExplainCmd())

	// Workflow & CI
	root.AddCommand(enforce.NewStatusCmd())

	snapshotCmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Snapshot lifecycle commands",
		Long:  "Grouped snapshot lifecycle commands: cleanup, archive, upcoming, quality, plan, hygiene, diff, manifest." + OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}
	root.AddCommand(snapshotCmd)
	wireSnapshotSubtree(snapshotCmd)

	ciCmd := &cobra.Command{
		Use:   "ci",
		Short: "CI/CD policy and baseline commands",
		Long:  "Grouped CI/CD commands: baseline, gate, fix-loop, diff, fix." + OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}
	root.AddCommand(ciCmd)
	wireCISubtree(ciCmd)

	// Data & Artifacts
	root.AddCommand(ingest.NewIngestCmd(ui.DefaultRuntime()))
	root.AddCommand(enforce.NewGenerateCmd())
	root.AddCommand(diagreport.NewReportCmd())

	// Settings
	root.AddCommand(initconfig.NewConfigCmd(ui.DefaultRuntime(), app.ConfigKeyService))
}

func wireSnapshotSubtree(snapshotCmd *cobra.Command) {
	snapshotCmd.AddCommand(enforce.NewDiffCmd())
	for _, subCmd := range prune.Commands() {
		snapshotCmd.AddCommand(subCmd)
	}
}

func wireCISubtree(ciCmd *cobra.Command) {
	ciCmd.AddCommand(enforce.NewBaselineCmd())
	ciCmd.AddCommand(enforce.NewGateCmd())
	ciCmd.AddCommand(enforce.NewFixLoopCmd())
	ciCmd.AddCommand(enforce.NewCiDiffCmd())
	ciCmd.AddCommand(enforce.NewFixCmd())
}

func assignCommandGroup(root *cobra.Command, use, groupID string) {
	cmd, _, err := root.Find([]string{use})
	if err != nil || cmd == nil {
		return
	}
	cmd.GroupID = groupID
}
