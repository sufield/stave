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
	stavebundle "github.com/sufield/stave/cmd/bundle"
	catalog "github.com/sufield/stave/cmd/catalog"
	stavecelcmd "github.com/sufield/stave/cmd/cel"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	stavecompare "github.com/sufield/stave/cmd/compare"
	contract "github.com/sufield/stave/cmd/contract"
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
	staveexempt "github.com/sufield/stave/cmd/exempt"
	"github.com/sufield/stave/cmd/expand"
	staveexport "github.com/sufield/stave/cmd/export"
	staveexportinvariants "github.com/sufield/stave/cmd/exportinvariants"
	staveexportsir "github.com/sufield/stave/cmd/exportsir"
	stavefeatures "github.com/sufield/stave/cmd/features"
	stavefingerprint "github.com/sufield/stave/cmd/fingerprint"
	staveforge "github.com/sufield/stave/cmd/forge"
	stavegaps "github.com/sufield/stave/cmd/gaps"
	"github.com/sufield/stave/cmd/initcmd"
	initalias "github.com/sufield/stave/cmd/initcmd/alias"
	initconfig "github.com/sufield/stave/cmd/initcmd/config"
	"github.com/sufield/stave/cmd/inspect"
	stavemap "github.com/sufield/stave/cmd/map"
	stavemetrics "github.com/sufield/stave/cmd/metrics"
	stavenep "github.com/sufield/stave/cmd/nep"
	stavepath "github.com/sufield/stave/cmd/path"
	staveprofile "github.com/sufield/stave/cmd/profile"
	stavereadiness "github.com/sufield/stave/cmd/readiness"
	stavereport "github.com/sufield/stave/cmd/report"
	stavesanitize "github.com/sufield/stave/cmd/sanitize"
	stavescore "github.com/sufield/stave/cmd/score"
	stavescorecard "github.com/sufield/stave/cmd/scorecard"
	search "github.com/sufield/stave/cmd/search"
	stavesnapshotdiff "github.com/sufield/stave/cmd/snapshotdiff"
	stavetelemetry "github.com/sufield/stave/cmd/telemetry"
	stavetest "github.com/sufield/stave/cmd/test"
	stavetrend "github.com/sufield/stave/cmd/trend"
	validatemapping "github.com/sufield/stave/cmd/validatemapping"
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

	// Getting started
	root.AddCommand(initcmd.NewGenerateCmd())

	// Control Engine
	root.AddCommand(applyvalidate.NewCmd(f.NewObsRepo, f.NewCtlRepo, f.NewCELEvaluator, ui.DefaultRuntime()))
	applyDeps := apply.Deps{
		NewObsRepo:       f.NewObsRepo,
		NewCtlRepo:       f.NewCtlRepo,
		NewStdinObsRepo:  f.NewStdinObsRepo,
		NewFindingWriter: f.NewFindingWriter,
		NewCELEvaluator:  f.NewCELEvaluator,
		NewChainLoader:   f.NewChainLoader,
		NewSLALoader:     f.NewSLALoader,
	}
	if err := applyDeps.Validate(); err != nil {
		return fmt.Errorf("validate apply deps: %w", err)
	}
	root.AddCommand(apply.NewApplyCmd(applyDeps))
	root.AddCommand(applyverify.NewCmd(f.NewObsRepo, f.NewCtlRepo, f.NewCELEvaluator, ui.DefaultRuntime()))
	diagnoseCmd := diagnose.NewDiagnoseCmd(f.NewObsRepo, f.NewCtlRepo)
	diagnoseCmd.AddCommand(diagnose.NewTraceCmd(f.NewCtlRepo, f.NewSnapshotRepo))
	diagnoseCmd.AddCommand(diagnose.NewExplainNarrativeCmd())
	// diagreport (cmd/diagnose/report) renders an evaluation JSON
	// document as text/JSON. It lives under `diagnose` because that
	// is where its source package lives and because two different
	// commands previously declared Use:"report" at the root —
	// stavereport.NewCmd (executive posture report, wired below) and
	// this one. Cobra last-write-wins resolved the collision in favour
	// of the executive command, leaving the diagnostic renderer
	// unreachable. Wiring it as a subcommand of `diagnose` matches the
	// package path and resolves the collision; the executive
	// `stave report` keeps the root namespace.
	reportLoader, rlErr := infrareport.NewEvaluationLoader(func(ctx context.Context, path string) (*report.Assessment, error) {
		return artifact.NewLoader().Evaluation(ctx, fsutil.CleanUserPath(path))
	})
	if rlErr != nil {
		return fmt.Errorf("wire report loader: %w", rlErr)
	}
	diagnoseCmd.AddCommand(diagreport.NewReportCmd(diagreport.Deps{
		UseCaseDeps: reporting.ReportDeps{Loader: reportLoader},
	}))
	root.AddCommand(diagnoseCmd)
	root.AddCommand(diagnose.NewExplainCmd(f.NewCtlRepo))
	root.AddCommand(expand.NewCmd(f.NewCtlRepo))

	// Workflow & CI
	root.AddCommand(enforce.NewStatusCmd())

	snapshotCmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Snapshot inspection commands",
		Long:  "Grouped snapshot commands: diff." + OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}
	root.AddCommand(snapshotCmd)
	wireSnapshotSubtree(snapshotCmd, loadSnapshots)

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

	// Capability scope
	root.AddCommand(stavefeatures.NewCmd())

	// Policy fingerprint diagnostics
	root.AddCommand(stavefingerprint.NewCmd())

	// Export & Interop
	root.AddCommand(staveexport.NewCmd(f.NewCtlRepo, f.NewCELEvaluator))
	root.AddCommand(staveexportinvariants.NewCmd())
	root.AddCommand(staveexportsir.NewCmd())

	// Data & Artifacts
	root.AddCommand(enforce.NewGenerateCmd())
	root.AddCommand(artifacts.NewLintCmd())
	root.AddCommand(artifacts.NewFmtCmd())
	root.AddCommand(artifacts.NewControlsCmd(f.NewCtlRepo))
	root.AddCommand(artifacts.NewPacksCmd())

	// Introspection
	root.AddCommand(inspect.NewInspectCmd())

	// Net Effective Permissions (CIEM)
	root.AddCommand(stavenep.NewCmd())

	// CEL expression tools
	root.AddCommand(stavecelcmd.NewCmd())

	// Security chronology
	root.AddCommand(stavebisect.NewCmd(stavebisect.Deps{
		NewCtlRepo:      f.NewCtlRepo,
		NewCELEvaluator: f.NewCELEvaluator,
	}))

	// Evidence bundling
	root.AddCommand(stavebundle.NewCmd())

	// Snapshot attestation
	root.AddCommand(staveattest.NewCmd())

	// Control authoring
	root.AddCommand(staveforge.NewCmd())

	// Posture trending
	root.AddCommand(stavetrend.NewCmd())

	// Risk acceptance management
	root.AddCommand(staveexempt.NewCmd(staveexempt.Deps{
		NewBuiltinControlStore: f.NewBuiltinControlStore,
	}))

	// ATT&CK coverage map
	root.AddCommand(stavemap.NewCmd(stavemap.Deps{
		NewCtlRepo: f.NewCtlRepo,
	}))

	// Attack path graph export
	root.AddCommand(stavepath.NewCmd())

	// Field coverage analysis
	root.AddCommand(stavecoverage.NewCmd(f.NewCtlRepo))

	// Control test runner. cmd/test migrated to the pkg/stave
	// facade (commit X); construction (control loader + CEL
	// evaluator) moved inside stave.RunControlTests so deps
	// injection is no longer needed at registration time.
	root.AddCommand(stavetest.NewCmd())

	// Pre-evaluation readiness assessment (catalog coverage
	// vs observation surface — distinct from `apply --dry-run`,
	// which is schema-validity only). Migrated to the pkg/stave
	// facade in Step 2; takes no Deps (loading is the library's
	// responsibility — see docs/architecture/pkg-stave-facade.md).
	root.AddCommand(stavereadiness.NewCmd())

	// Field-level gap analysis — drills past asset-type
	// coverage (stave readiness) into per-property absence
	// and the controls/chains each absence blocks. Migrated to
	// the pkg/stave facade; takes no Deps (loading is the
	// library's responsibility — see docs/architecture/pkg-stave-facade.md).
	root.AddCommand(stavegaps.NewCmd())

	// Per-asset-type contract introspection — joins the per-asset
	// JSON Schema, the predicate-path index, and the Steampipe
	// mapping directory into one agent-facing view.
	root.AddCommand(contract.NewCmd(contract.Deps{
		NewCtlRepo:     f.NewCtlRepo,
		NewChainLoader: f.NewChainLoader,
	}))

	// Steampipe→Stave mapping validation. Lets an agent confirm a
	// generated contracts/steampipe/*.yaml is well-formed, references
	// only declared schema paths, and covers the catalog's read
	// surface for that asset type before it ships an observation.
	root.AddCommand(validatemapping.NewCmd(validatemapping.Deps{
		NewCtlRepo:     f.NewCtlRepo,
		NewChainLoader: f.NewChainLoader,
	}))

	// Free-form search across controls + chains + asset types.
	// Bridges user intent ("public S3 bucket") to catalog vocabulary
	// without forcing the user to know the taxonomy first.
	root.AddCommand(search.NewCmd(search.Deps{
		NewCtlRepo:     f.NewCtlRepo,
		NewChainLoader: f.NewChainLoader,
	}))

	// Multi-framework scorecard
	root.AddCommand(stavescorecard.NewCmd())

	// Snapshot diff
	root.AddCommand(stavesnapshotdiff.NewCmd(f.NewCtlRepo))

	// Standalone sanitization
	root.AddCommand(stavesanitize.NewCmd())

	// Prometheus metrics export
	root.AddCommand(stavemetrics.NewCmd())

	// Profile management
	root.AddCommand(staveprofile.NewCmd())

	// Compliance gap analysis
	root.AddCommand(stavecompare.NewCmd())

	// Executive report
	reportDeps := stavereport.Deps{
		NewChainLoader:          f.NewChainLoader,
		NewSLALoader:            f.NewSLALoader,
		NewArtifactLoader:       f.NewArtifactLoader,
		NewSnapshotBundleLoader: f.NewSnapshotBundleLoader,
		NewCtlRepo:              f.NewCtlRepo,
	}
	if err := reportDeps.Validate(); err != nil {
		return fmt.Errorf("validate report deps: %w", err)
	}
	root.AddCommand(stavereport.NewCmd(reportDeps))

	// Posture score
	root.AddCommand(stavescore.NewCmd())

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
	{
		capabilitiesCmd := newCapabilitiesCmd()
		capabilitiesCmd.AddCommand(catalog.NewCmd(catalog.Deps{
			NewCtlRepo:     f.NewCtlRepo,
			NewChainLoader: f.NewChainLoader,
		}))
		root.AddCommand(capabilitiesCmd)
	}
	root.AddCommand(newCompletionCmd())
	root.AddCommand(newSchemasCmd())
	root.AddCommand(newVersionCmd(app.Edition))

	// Settings
	root.AddCommand(initconfig.NewConfigCmd(ui.DefaultRuntime()))
	return nil
}

func wireSnapshotSubtree(
	snapshotCmd *cobra.Command,
	loadSnapshots compose.SnapshotLoader,
) {
	snapshotCmd.AddCommand(enforce.NewDiffCmd(loadSnapshots))
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
// simply has fewer of them. Soft-skip logging is slog.Debug, not
// slog.Warn, because edition stripping is the normal case for
// release builds — the WARN was firing on every `stave --help`
// invocation and felt like a bug to users.
func assignCommandGroup(root *cobra.Command, use, groupID string) {
	cmd, _, err := root.Find([]string{use})
	if err != nil {
		slog.Debug("assignCommandGroup: subcommand not present in this build; skipping",
			"use", use, "group_id", groupID, "error", err)
		return
	}
	// Cobra's Find returns the root command (no error) when no
	// matching subcommand exists. Stamping GroupID onto the root
	// would corrupt the help layout, so the same soft-skip rule
	// applies.
	if cmd == nil || cmd == root {
		slog.Debug("assignCommandGroup: subcommand not present in this build; skipping",
			"use", use, "group_id", groupID)
		return
	}
	cmd.GroupID = groupID
}
