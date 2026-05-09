package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/ports"

	"github.com/sufield/stave/cmd/apply"
	applyvalidate "github.com/sufield/stave/cmd/apply/validate"
	applyverify "github.com/sufield/stave/cmd/apply/verify"
	staveattest "github.com/sufield/stave/cmd/attest"
	stavebisect "github.com/sufield/stave/cmd/bisect"
	stavebudget "github.com/sufield/stave/cmd/budget"
	stavebundle "github.com/sufield/stave/cmd/bundle"
	stavecelcmd "github.com/sufield/stave/cmd/cel"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	stavecollect "github.com/sufield/stave/cmd/collect"
	stavecompare "github.com/sufield/stave/cmd/compare"
	staveconsolidate "github.com/sufield/stave/cmd/consolidate"
	stavecoverage "github.com/sufield/stave/cmd/coverage"
	"github.com/sufield/stave/cmd/diagnose"
	"github.com/sufield/stave/cmd/diagnose/artifacts"
	diagreport "github.com/sufield/stave/cmd/diagnose/report"
	"github.com/sufield/stave/cmd/doctor"
	"github.com/sufield/stave/cmd/enforce"
	"github.com/sufield/stave/cmd/enforce/baseline"
	"github.com/sufield/stave/cmd/enforce/cidiff"
	"github.com/sufield/stave/cmd/enforce/fix"
	"github.com/sufield/stave/cmd/enforce/gate"
	staveenrich "github.com/sufield/stave/cmd/enrich"
	staveexempt "github.com/sufield/stave/cmd/exempt"
	"github.com/sufield/stave/cmd/expand"
	staveexport "github.com/sufield/stave/cmd/export"
	staveexportinvariants "github.com/sufield/stave/cmd/exportinvariants"
	staveexportsir "github.com/sufield/stave/cmd/exportsir"
	staveforensics "github.com/sufield/stave/cmd/forensics"
	staveforge "github.com/sufield/stave/cmd/forge"
	"github.com/sufield/stave/cmd/initcmd"
	initalias "github.com/sufield/stave/cmd/initcmd/alias"
	initconfig "github.com/sufield/stave/cmd/initcmd/config"
	"github.com/sufield/stave/cmd/inspect"
	staveinventory "github.com/sufield/stave/cmd/inventory"
	stavemap "github.com/sufield/stave/cmd/map"
	stavemetrics "github.com/sufield/stave/cmd/metrics"
	stavemonitor "github.com/sufield/stave/cmd/monitor"
	stavenep "github.com/sufield/stave/cmd/nep"
	stavepath "github.com/sufield/stave/cmd/path"
	staveplan "github.com/sufield/stave/cmd/plan"
	staveprofile "github.com/sufield/stave/cmd/profile"
	"github.com/sufield/stave/cmd/prune"
	staverank "github.com/sufield/stave/cmd/rank"
	stavereport "github.com/sufield/stave/cmd/report"
	stavesanitize "github.com/sufield/stave/cmd/sanitize"
	stavescore "github.com/sufield/stave/cmd/score"
	stavescorecard "github.com/sufield/stave/cmd/scorecard"
	stavesimulate "github.com/sufield/stave/cmd/simulate"
	stavesla "github.com/sufield/stave/cmd/sla"
	stavesnapshotdiff "github.com/sufield/stave/cmd/snapshotdiff"
	stavetelemetry "github.com/sufield/stave/cmd/telemetry"
	stavetest "github.com/sufield/stave/cmd/test"
	stavetrend "github.com/sufield/stave/cmd/trend"
	staveverify "github.com/sufield/stave/cmd/verify"
	stavewatch "github.com/sufield/stave/cmd/watch"
	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	infrabaseline "github.com/sufield/stave/internal/adapters/baseline"
	infradoctor "github.com/sufield/stave/internal/adapters/doctor"
	evaljson "github.com/sufield/stave/internal/adapters/evaluation"
	infrareport "github.com/sufield/stave/internal/adapters/report"
	infrafix "github.com/sufield/stave/internal/app/fix"
	"github.com/sufield/stave/internal/cli/ui"
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

// WireCommands attaches the full command tree to the root command and
// returns any wiring error encountered. Callers (NewApp) propagate to
// the executor, which exits with ExitInternal so the operator sees the
// failure on stderr instead of a panic stack trace.
// This is intentionally the single command registration point for the entire CLI.
// Every command and subcommand is registered here so the full tree is visible
// in one place. Do not split registration across packages — that makes the
// command hierarchy harder to reason about and the registration order non-obvious.
func WireCommands(app *App) error {
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
	root.AddCommand(initcmd.NewGenerateCmd())

	// Control Engine
	root.AddCommand(applyvalidate.NewCmd(f.NewObsRepo, f.NewCtlRepo, f.NewCELEvaluator, ui.DefaultRuntime()))
	root.AddCommand(apply.NewApplyCmd(apply.Deps{
		NewObsRepo:       f.NewObsRepo,
		NewCtlRepo:       f.NewCtlRepo,
		NewStdinObsRepo:  f.NewStdinObsRepo,
		NewFindingWriter: f.NewFindingWriter,
		NewCELEvaluator:  f.NewCELEvaluator,
		NewChainLoader:   f.NewChainLoader,
		NewSLALoader:     f.NewSLALoader,
	}))
	root.AddCommand(applyverify.NewCmd(f.NewObsRepo, f.NewCtlRepo, f.NewCELEvaluator, ui.DefaultRuntime()))
	diagnoseCmd := diagnose.NewDiagnoseCmd(f.NewObsRepo, f.NewCtlRepo)
	diagnoseCmd.AddCommand(diagnose.NewTraceCmd(f.NewCtlRepo, f.NewSnapshotRepo))
	diagnoseCmd.AddCommand(diagnose.NewExplainNarrativeCmd())
	root.AddCommand(diagnoseCmd)
	root.AddCommand(diagnose.NewExplainCmd(f.NewCtlRepo))
	root.AddCommand(expand.NewCmd(f.NewCtlRepo))

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
	if err := wireCISubtree(ciCmd, f.NewCELEvaluator, f.NewCtlRepo, f.NewObsRepo); err != nil {
		return err
	}

	// Export & Interop
	root.AddCommand(staveexport.NewCmd(f.NewCtlRepo, f.NewCELEvaluator))
	root.AddCommand(staveexportinvariants.NewCmd())
	root.AddCommand(staveexportsir.NewCmd(f.NewCtlRepo, f.NewObsRepo, f.NewCELEvaluator))

	// Data & Artifacts
	root.AddCommand(enforce.NewGenerateCmd())
	reportLoader, rlErr := infrareport.NewEvaluationLoader(func(ctx context.Context, path string) (*report.Assessment, error) {
		return artifact.NewLoader().Evaluation(ctx, fsutil.CleanUserPath(path))
	})
	if rlErr != nil {
		return fmt.Errorf("wire report loader: %w", rlErr)
	}
	root.AddCommand(diagreport.NewReportCmd(diagreport.Deps{
		UseCaseDeps: reporting.ReportDeps{Loader: reportLoader},
	}))
	root.AddCommand(artifacts.NewLintCmd())
	root.AddCommand(artifacts.NewFmtCmd())
	root.AddCommand(artifacts.NewControlsCmd(f.NewCtlRepo))
	root.AddCommand(artifacts.NewPacksCmd())

	// Introspection
	root.AddCommand(inspect.NewInspectCmd(f.NewS3Resolver))

	// Net Effective Permissions (CIEM)
	root.AddCommand(stavenep.NewCmd())

	// CEL expression tools
	root.AddCommand(stavecelcmd.NewCmd())

	// Security chronology
	root.AddCommand(stavebisect.NewCmd())

	// Continuous monitoring
	root.AddCommand(stavewatch.NewCmd())

	// Evidence bundling
	root.AddCommand(stavebundle.NewCmd())

	// Snapshot attestation
	root.AddCommand(staveattest.NewCmd())

	// Control authoring
	root.AddCommand(staveforge.NewCmd())

	// Posture trending
	root.AddCommand(stavetrend.NewCmd())

	// Remediation ranking
	root.AddCommand(staverank.NewCmd())

	// Multi-account consolidation
	root.AddCommand(staveconsolidate.NewCmd())

	// Risk acceptance management
	root.AddCommand(staveexempt.NewCmd())

	// Automated evidence collection
	root.AddCommand(stavecollect.NewCmd())

	// Forensic timeline reconstruction
	root.AddCommand(staveforensics.NewCmd())

	// ATT&CK coverage map
	root.AddCommand(stavemap.NewCmd())

	// Attack path graph export
	root.AddCommand(stavepath.NewCmd())

	// Field coverage analysis
	root.AddCommand(stavecoverage.NewCmd(f.NewCtlRepo))

	// Control test runner
	root.AddCommand(stavetest.NewCmd(f.NewCtlRepo))

	// Terminal posture monitor
	root.AddCommand(stavemonitor.NewCmd())

	// Multi-framework scorecard
	root.AddCommand(stavescorecard.NewCmd())

	// Snapshot diff
	root.AddCommand(stavesnapshotdiff.NewCmd(f.NewCtlRepo))

	// Standalone sanitization
	root.AddCommand(stavesanitize.NewCmd())

	// Prometheus metrics export
	root.AddCommand(stavemetrics.NewCmd())

	// CVE/NVD enrichment
	root.AddCommand(staveenrich.NewCmd())

	// Profile management
	root.AddCommand(staveprofile.NewCmd())

	// Version inventory for CVE correlation
	root.AddCommand(staveinventory.NewCmd())

	// Remediation simulation
	root.AddCommand(stavesimulate.NewCmd())

	// Compliance gap analysis
	root.AddCommand(stavecompare.NewCmd())

	// Team remediation plans
	root.AddCommand(staveplan.NewCmd())

	// Executive report
	root.AddCommand(stavereport.NewCmd())

	// Evidence archive verification
	root.AddCommand(staveverify.NewCmd())

	// SLA policy management
	root.AddCommand(stavesla.NewCmd())

	// Posture score
	root.AddCommand(stavescore.NewCmd())

	// Security budget / burn rate
	root.AddCommand(stavebudget.NewCmd())

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
	return nil
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
) error {
	// DirPerms defaults to 0o755: the parent dir for the baseline
	// file might not exist on first run, and SafeMkdirAll passes the
	// FileMode through to os.Mkdir verbatim — a zero DirPerms would
	// create the directory with mode 0000 (no rwx for anyone) and
	// the subsequent SafeCreateFile would fail with "permission
	// denied" on a directory we just made ourselves.
	baselineFileOpts := fileout.FileOptions{DirPerms: 0o755}

	baselineWriter, bwErr := infrabaseline.NewWriter(func(path string) (*os.File, error) {
		return fileout.OpenOutputFile(path, baselineFileOpts)
	})
	if bwErr != nil {
		return fmt.Errorf("wire baseline writer: %w", bwErr)
	}
	ciCmd.AddCommand(enforce.NewBaselineCmd(baseline.Deps{
		SaveDeps: reporting.BaselineSaveDeps{
			Loader: &infrabaseline.EvaluationLoader{},
			Writer: baselineWriter,
			Clock:  ports.RealClock{},
		},
		CheckDeps: reporting.BaselineCheckDeps{
			EvalLoader:     &infrabaseline.EvaluationLoader{},
			BaselineLoader: &infrabaseline.Loader{},
			Clock:          ports.RealClock{},
		},
	}))
	// Gate adapters (FindingsCounter, BaselineComparer, OverdueCounter)
	// are now wired internally by pkg/stave.Gate; the gate command
	// no longer accepts dependency injection at this boundary.
	ciCmd.AddCommand(enforce.NewGateCmd(gate.Deps{}))
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
	ciCmd.AddCommand(enforce.NewFixCmd(fix.Deps{
		NewLoader: func() (usecase.FindingLoaderPort, error) {
			celEval, err := newCELEvaluator()
			if err != nil {
				return nil, fmt.Errorf("initialize CEL evaluator for fix command: %w", err)
			}
			return infrafix.NewFindingLoader(celEval, fsutil.ReadFileLimited, evaljson.ParseFindings)
		},
	}))
	return nil
}

// assignCommandGroup stamps the named subcommand with the given help
// group ID. A subcommand that is not registered in this build (the
// edition-stripped case) is treated as a soft skip: the help groupMap
// names every command that could exist, and a stripped edition
// simply has fewer of them. Genuine wiring bugs surface as the
// slog.Warn calls below; there is no error return because every
// outcome here is recoverable.
func assignCommandGroup(root *cobra.Command, use, groupID string) {
	cmd, _, err := root.Find([]string{use})
	if err != nil {
		slog.Warn("assignCommandGroup: subcommand not present in this build; skipping",
			"use", use, "group_id", groupID, "error", err)
		return
	}
	// Cobra's Find returns the root command (no error) when no
	// matching subcommand exists. Stamping GroupID onto the root
	// would corrupt the help layout, so the same soft-skip rule
	// applies.
	if cmd == nil || cmd == root {
		slog.Warn("assignCommandGroup: subcommand not present in this build; skipping",
			"use", use, "group_id", groupID)
		return
	}
	cmd.GroupID = groupID
}
