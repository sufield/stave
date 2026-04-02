package cmd

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/core/ports"

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
	"github.com/sufield/stave/cmd/enforce/baseline"
	"github.com/sufield/stave/cmd/enforce/cidiff"
	"github.com/sufield/stave/cmd/enforce/fix"
	"github.com/sufield/stave/cmd/enforce/gate"
	"github.com/sufield/stave/cmd/evaluate"
	"github.com/sufield/stave/cmd/initcmd"
	initalias "github.com/sufield/stave/cmd/initcmd/alias"
	initconfig "github.com/sufield/stave/cmd/initcmd/config"
	"github.com/sufield/stave/cmd/inspect"
	"github.com/sufield/stave/cmd/prune"
	"github.com/sufield/stave/cmd/securityaudit"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/eval"
	"github.com/sufield/stave/internal/core/reporting"
	"github.com/sufield/stave/internal/core/setup"
	infrabaseline "github.com/sufield/stave/internal/infra/baseline"
	infradoctor "github.com/sufield/stave/internal/infra/doctor"
	infrafix "github.com/sufield/stave/internal/infra/fix"
	infragate "github.com/sufield/stave/internal/infra/gate"
	infrareport "github.com/sufield/stave/internal/infra/report"
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

// WireCommands attaches the full command tree to the root command.
// This is intentionally the single command registration point for the entire CLI.
// Every command and subcommand is registered here so the full tree is visible
// in one place. Do not split registration across packages — that makes the
// command hierarchy harder to reason about and the registration order non-obvious.
func WireCommands(app *App) {
	root := app.Root
	p := app.Provider

	// Getting started
	root.AddCommand(initcmd.NewInitCmd())
	root.AddCommand(initcmd.NewGenerateCmd())

	// Control Engine
	root.AddCommand(applyvalidate.NewCmd(p.NewObservationRepo, p.NewControlRepo, p.NewCELEvaluator, ui.DefaultRuntime()))
	root.AddCommand(apply.NewApplyCmd(p))
	root.AddCommand(applyverify.NewCmd(p.NewObservationRepo, p.NewControlRepo, p.NewCELEvaluator, ui.DefaultRuntime()))
	root.AddCommand(diagnose.NewDiagnoseCmd(p.NewObservationRepo, p.NewControlRepo))
	root.AddCommand(diagnose.NewExplainCmd(p.NewControlRepo))
	root.AddCommand(diagnose.NewTraceCmd(p.NewControlRepo, p.NewSnapshotRepo))
	root.AddCommand(diagnose.NewPromptCmd(p.NewControlRepo, p.LoadSnapshots))

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
	root.AddCommand(diagreport.NewReportCmd(diagreport.Deps{
		UseCaseDeps: reporting.ReportDeps{
			Loader: &infrareport.EvaluationLoader{},
		},
	}))
	root.AddCommand(artifacts.NewLintCmd())
	root.AddCommand(artifacts.NewFmtCmd())
	root.AddCommand(artifacts.NewControlsCmd(p.NewControlRepo))
	root.AddCommand(artifacts.NewPacksCmd())

	// Introspection
	root.AddCommand(inspect.NewInspectCmd())

	// Security
	root.AddCommand(securityaudit.NewCmd())

	// Compliance evaluation
	root.AddCommand(evaluate.NewCmd())

	// Supportability
	root.AddCommand(doctor.NewCmd(doctor.Deps{
		UseCaseDeps: setup.DoctorDeps{
			Runner: &infradoctor.CheckRunner{},
		},
	}))
	root.AddCommand(bugreport.NewCmd())
	root.AddCommand(enforce.NewGraphCmd(p.NewControlRepo, p.LoadSnapshots))
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
	snapshotCmd.AddCommand(enforce.NewDiffCmd(p.LoadSnapshots))
	for _, subCmd := range prune.Commands(p) {
		snapshotCmd.AddCommand(subCmd)
	}
	for _, subCmd := range prune.DevCommands(p) {
		snapshotCmd.AddCommand(subCmd)
	}
}

func wireCISubtree(ciCmd *cobra.Command, p *compose.Provider) {
	ciCmd.AddCommand(enforce.NewBaselineCmd(baseline.Deps{
		SaveDeps: reporting.BaselineSaveDeps{
			Loader: &infrabaseline.EvaluationLoader{},
			Writer: &infrabaseline.BaselineWriter{},
			Clock:  ports.RealClock{},
		},
		CheckDeps: reporting.BaselineCheckDeps{
			EvalLoader:     &infrabaseline.EvaluationLoader{},
			BaselineLoader: &infrabaseline.BaselineLoader{},
			Clock:          ports.RealClock{},
		},
	}))
	ciCmd.AddCommand(enforce.NewGateCmd(gate.Deps{
		UseCaseDeps: eval.GateDeps{
			FindingsCounter:  &infragate.FindingsCounter{},
			BaselineComparer: &infragate.BaselineComparer{},
			OverdueCounter: &infragate.OverdueCounter{
				LoadAssets:      p.LoadAssets,
				NewCELEvaluator: p.NewCELEvaluator,
			},
			Clock: ports.RealClock{},
		},
	}))
	ciCmd.AddCommand(enforce.NewFixLoopCmd(fix.FixLoopDeps{
		NewCELEvaluator: p.NewCELEvaluator,
		NewCtlRepo:      p.NewControlRepo,
		NewObsRepo:      p.NewObservationRepo,
	}))
	ciCmd.AddCommand(enforce.NewCiDiffCmd(cidiff.Deps{
		UseCaseDeps: reporting.CIDiffDeps{
			CurrentLoader:  &infrabaseline.EvaluationLoader{},
			BaselineLoader: &infrabaseline.EvaluationLoader{},
			Clock:          ports.RealClock{},
		},
	}))
	celEval, _ := p.NewCELEvaluator()
	ciCmd.AddCommand(enforce.NewFixCmd(fix.FixDeps{
		UseCaseDeps: eval.FixDeps{
			Loader: &infrafix.FindingLoader{CELEvaluator: celEval},
		},
	}))
}

func assignCommandGroup(root *cobra.Command, use, groupID string) {
	cmd, _, err := root.Find([]string{use})
	if err != nil || cmd == nil {
		return
	}
	cmd.GroupID = groupID
}
