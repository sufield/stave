package cmd

import (
	"context"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/ports"

	"github.com/sufield/stave/cmd/apply"
	applyvalidate "github.com/sufield/stave/cmd/apply/validate"
	applyverify "github.com/sufield/stave/cmd/apply/verify"
	stavebisect "github.com/sufield/stave/cmd/bisect"
	stavebundle "github.com/sufield/stave/cmd/bundle"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/diagnose"
	"github.com/sufield/stave/cmd/diagnose/artifacts"
	diagreport "github.com/sufield/stave/cmd/diagnose/report"
	"github.com/sufield/stave/cmd/doctor"
	stavedrift "github.com/sufield/stave/cmd/drift"
	"github.com/sufield/stave/cmd/enforce"
	"github.com/sufield/stave/cmd/enforce/baseline"
	"github.com/sufield/stave/cmd/enforce/cidiff"
	"github.com/sufield/stave/cmd/enforce/fix"
	"github.com/sufield/stave/cmd/enforce/gate"
	"github.com/sufield/stave/cmd/evaluate"
	staveexport "github.com/sufield/stave/cmd/export"
	staveforge "github.com/sufield/stave/cmd/forge"
	"github.com/sufield/stave/cmd/initcmd"
	initalias "github.com/sufield/stave/cmd/initcmd/alias"
	initconfig "github.com/sufield/stave/cmd/initcmd/config"
	"github.com/sufield/stave/cmd/inspect"
	stavenep "github.com/sufield/stave/cmd/nep"
	"github.com/sufield/stave/cmd/prune"
	staverank "github.com/sufield/stave/cmd/rank"
	stavetelemetry "github.com/sufield/stave/cmd/telemetry"
	stavetrend "github.com/sufield/stave/cmd/trend"
	stavewatch "github.com/sufield/stave/cmd/watch"
	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	infrabaseline "github.com/sufield/stave/internal/adapters/baseline"
	infradoctor "github.com/sufield/stave/internal/adapters/doctor"
	infrafix "github.com/sufield/stave/internal/adapters/fix"
	infragate "github.com/sufield/stave/internal/adapters/gate"
	infrareport "github.com/sufield/stave/internal/adapters/report"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/core/reporting"
	"github.com/sufield/stave/internal/core/setup"
	"github.com/sufield/stave/internal/core/usecase"
	"github.com/sufield/stave/internal/platform/fileout"
	"github.com/sufield/stave/internal/platform/fsutil"
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
	f := compose.DefaultFactories()

	// Convenience closures for commands that need composed loaders.
	loadSnapshots := func(ctx context.Context, dir string) ([]asset.Snapshot, error) {
		return compose.LoadSnapshotsFrom(ctx, f.NewObsRepo, dir)
	}
	loadAssets := func(ctx context.Context, obsDir, ctlDir string) (compose.Assets, error) {
		return compose.LoadAssets(ctx, f.NewObsRepo, f.NewCtlRepo, obsDir, ctlDir)
	}

	// Getting started
	root.AddCommand(initcmd.NewInitCmd())
	root.AddCommand(initcmd.NewGenerateCmd())

	// Control Engine
	root.AddCommand(applyvalidate.NewCmd(f.NewObsRepo, f.NewCtlRepo, f.NewCELEvaluator, ui.DefaultRuntime()))
	root.AddCommand(apply.NewApplyCmd(apply.Deps{
		NewObsRepo:       f.NewObsRepo,
		NewCtlRepo:       f.NewCtlRepo,
		NewStdinObsRepo:  f.NewStdinObsRepo,
		NewFindingWriter: f.NewFindingWriter,
		NewCELEvaluator:  f.NewCELEvaluator,
	}))
	root.AddCommand(applyverify.NewCmd(f.NewObsRepo, f.NewCtlRepo, f.NewCELEvaluator, ui.DefaultRuntime()))
	root.AddCommand(diagnose.NewDiagnoseCmd(f.NewObsRepo, f.NewCtlRepo))
	root.AddCommand(diagnose.NewExplainCmd(f.NewCtlRepo))
	root.AddCommand(diagnose.NewTraceCmd(f.NewCtlRepo, f.NewSnapshotRepo))
	root.AddCommand(diagnose.NewPromptCmd(f.NewCtlRepo, loadSnapshots))

	// Workflow & CI
	root.AddCommand(enforce.NewStatusCmd())

	snapshotCmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Snapshot lifecycle commands",
		Long:  "Grouped snapshot lifecycle commands: cleanup, archive, upcoming, quality, plan, hygiene, diff, manifest." + OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}
	root.AddCommand(snapshotCmd)
	wireSnapshotSubtree(snapshotCmd, f.NewObsRepo, f.NewSnapshotRepo, loadAssets, loadSnapshots)

	ciCmd := &cobra.Command{
		Use:   "ci",
		Short: "CI/CD policy and baseline commands",
		Long:  "Grouped CI/CD commands: baseline, gate, fix-loop, diff, fix." + OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}
	root.AddCommand(ciCmd)
	wireCISubtree(ciCmd, f.NewCELEvaluator, f.NewCtlRepo, f.NewObsRepo, loadAssets)

	// Export & Interop
	root.AddCommand(staveexport.NewCmd(f.NewCtlRepo, f.NewCELEvaluator))

	// Data & Artifacts
	root.AddCommand(enforce.NewGenerateCmd())
	root.AddCommand(diagreport.NewReportCmd(diagreport.Deps{
		UseCaseDeps: reporting.ReportDeps{
			Loader: &infrareport.EvaluationLoader{
				LoadEval: func(ctx context.Context, path string) (*report.Assessment, error) {
					return artifact.NewLoader().Evaluation(ctx, fsutil.CleanUserPath(path))
				},
			},
		},
	}))
	root.AddCommand(artifacts.NewLintCmd())
	root.AddCommand(artifacts.NewFmtCmd())
	root.AddCommand(artifacts.NewControlsCmd(f.NewCtlRepo))
	root.AddCommand(artifacts.NewPacksCmd())

	// Introspection
	root.AddCommand(inspect.NewInspectCmd())

	// Compliance evaluation
	root.AddCommand(evaluate.NewCmd())

	// Net Effective Permissions (CIEM)
	root.AddCommand(stavenep.NewCmd())

	// Drift detection
	root.AddCommand(stavedrift.NewCmd())

	// Security chronology
	root.AddCommand(stavebisect.NewCmd())

	// Continuous monitoring
	root.AddCommand(stavewatch.NewCmd())

	// Evidence bundling
	root.AddCommand(stavebundle.NewCmd())

	// Control authoring
	root.AddCommand(staveforge.NewCmd())

	// Posture trending
	root.AddCommand(stavetrend.NewCmd())

	// Remediation ranking
	root.AddCommand(staverank.NewCmd())

	// Telemetry bridge
	root.AddCommand(stavetelemetry.NewCmd())

	// Supportability
	root.AddCommand(doctor.NewCmd(doctor.Deps{
		UseCaseDeps: setup.DoctorDeps{
			Runner: &infradoctor.CheckRunner{},
		},
	}))
	root.AddCommand(enforce.NewGraphCmd(f.NewCtlRepo, loadSnapshots))
	root.AddCommand(initalias.NewCmd(root))
	root.AddCommand(newCapabilitiesCmd())
	root.AddCommand(newCompletionCmd())
	root.AddCommand(newSchemasCmd())
	root.AddCommand(newVersionCmd(app.Edition))

	// Settings
	root.AddCommand(initconfig.NewConfigCmd(ui.DefaultRuntime()))
}

func wireSnapshotSubtree(
	snapshotCmd *cobra.Command,
	newObs compose.ObsRepoFactory,
	newSnapshot compose.SnapshotRepoFactory,
	loadAssets compose.AssetLoaderFunc,
	loadSnapshots compose.SnapshotLoader,
) {
	snapshotCmd.AddCommand(enforce.NewDiffCmd(loadSnapshots))
	for _, subCmd := range prune.Commands(newObs, newSnapshot, loadAssets, loadSnapshots) {
		snapshotCmd.AddCommand(subCmd)
	}
	for _, subCmd := range prune.DevCommands(newSnapshot) {
		snapshotCmd.AddCommand(subCmd)
	}
}

func wireCISubtree(
	ciCmd *cobra.Command,
	newCELEvaluator compose.CELEvaluatorFactory,
	newCtlRepo compose.CtlRepoFactory,
	newObsRepo compose.ObsRepoFactory,
	loadAssets compose.AssetLoaderFunc,
) {
	loader := artifact.NewLoader()

	baselineFileOpts := fileout.FileOptions{}

	ciCmd.AddCommand(enforce.NewBaselineCmd(baseline.Deps{
		SaveDeps: reporting.BaselineSaveDeps{
			Loader: &infrabaseline.EvaluationLoader{},
			Writer: &infrabaseline.Writer{
				OpenFile: func(path string) (*os.File, error) {
					return fileout.OpenOutputFile(path, baselineFileOpts)
				},
			},
			Clock: ports.RealClock{},
		},
		CheckDeps: reporting.BaselineCheckDeps{
			EvalLoader:     &infrabaseline.EvaluationLoader{},
			BaselineLoader: &infrabaseline.Loader{},
			Clock:          ports.RealClock{},
		},
	}))
	ciCmd.AddCommand(enforce.NewGateCmd(gate.Deps{
		UseCaseDeps: usecase.GateDeps{
			FindingsCounter: &infragate.FindingsCounter{
				LoadEvaluation: loader.Evaluation,
			},
			BaselineComparer: &infragate.BaselineComparer{
				LoadEvaluation: loader.Evaluation,
				LoadBaseline:   loader.Baseline,
				Compare: func(san kernel.Sanitizer, baseEntries []evaluation.BaselineEntry, currentFindings []remediation.Finding) infragate.BaselineComparisonResult {
					bc := artifact.CompareAgainstBaseline(san, baseEntries, currentFindings)
					return infragate.BaselineComparisonResult{
						Current:    bc.Current,
						Comparison: bc.Comparison,
					}
				},
			},
			OverdueCounter: &infragate.OverdueCounter{
				LoadAssets: func(ctx context.Context, obsDir, ctlDir string) (infragate.Assets, error) {
					a, err := loadAssets(ctx, obsDir, ctlDir)
					if err != nil {
						return infragate.Assets{}, err
					}
					return infragate.Assets{
						Snapshots: a.Snapshots,
						Controls:  a.Controls,
					}, nil
				},
				NewCELEvaluator: newCELEvaluator,
			},
			Clock: ports.RealClock{},
		},
	}))
	ciCmd.AddCommand(enforce.NewFixLoopCmd(fix.LoopDeps{
		NewCELEvaluator: newCELEvaluator,
		NewCtlRepo:      newCtlRepo,
		NewObsRepo:      newObsRepo,
	}))
	ciCmd.AddCommand(enforce.NewCiDiffCmd(cidiff.Deps{
		UseCaseDeps: reporting.CIDiffDeps{
			CurrentLoader:  &infrabaseline.EvaluationLoader{},
			BaselineLoader: &infrabaseline.EvaluationLoader{},
			Clock:          ports.RealClock{},
		},
	}))
	celEval, celErr := newCELEvaluator()
	if celErr != nil {
		panic("initialize CEL evaluator for fix command: " + celErr.Error())
	}
	ciCmd.AddCommand(enforce.NewFixCmd(fix.Deps{
		UseCaseDeps: usecase.FixDeps{
			Loader: &infrafix.FindingLoader{CELEvaluator: celEval, ReadFile: fsutil.ReadFileLimited},
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
