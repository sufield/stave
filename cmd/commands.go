package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	staveexport "github.com/sufield/stave/cmd/export"
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
	infrafix "github.com/sufield/stave/internal/adapters/fix"
	infragate "github.com/sufield/stave/internal/adapters/gate"
	infrareport "github.com/sufield/stave/internal/adapters/report"
	"github.com/sufield/stave/internal/app/snapshotquery"
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
	"github.com/sufield/stave/internal/util/jsonutil"
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
	diagnoseCmd := diagnose.NewDiagnoseCmd(f.NewObsRepo, f.NewCtlRepo)
	diagnoseCmd.AddCommand(diagnose.NewTraceCmd(f.NewCtlRepo, f.NewSnapshotRepo))
	diagnoseCmd.AddCommand(diagnose.NewPromptCmd(f.NewCtlRepo, loadSnapshots))
	diagnoseCmd.AddCommand(diagnose.NewExplainNarrativeCmd())
	root.AddCommand(diagnoseCmd)
	root.AddCommand(diagnose.NewExplainCmd(f.NewCtlRepo))

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
}

func wireSnapshotSubtree(
	snapshotCmd *cobra.Command,
	newObs compose.ObsRepoFactory,
	newSnapshot compose.SnapshotRepoFactory,
	loadAssets compose.AssetLoaderFunc,
	loadSnapshots compose.SnapshotLoader,
) {
	snapshotCmd.AddCommand(enforce.NewDiffCmd(loadSnapshots))
	snapshotCmd.AddCommand(newSnapshotQueryCmd())
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

func newSnapshotQueryCmd() *cobra.Command {
	var dir, olderThan, newerThan, format, now string
	var health bool

	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query snapshot archive metadata",
		Long: `Query scans an observation directory and returns metadata about each
snapshot file including captured_at timestamp, age, size, and schema validity.

Use --health to produce a summary health report of the archive.

Exit Codes:
  0   Query completed
  2   Invalid input
  4   Internal error`,
		Example: `  stave snapshot query --dir observations
  stave snapshot query --dir observations --older-than 720h
  stave snapshot query --dir observations --health
  stave snapshot query --dir observations --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dir == "" {
				dir = "observations"
			}

			nowTime := time.Now().UTC()
			if now != "" {
				t, err := time.Parse(time.RFC3339, now)
				if err != nil {
					return &ui.UserError{Err: fmt.Errorf("parse --now: %w", err)}
				}
				nowTime = t
			}

			stdout := cmd.OutOrStdout()

			if health {
				report, err := snapshotquery.Health(dir, nowTime)
				if err != nil {
					return fmt.Errorf("snapshot health: %w", err)
				}
				if format == "json" {
					return jsonutil.WriteIndented(stdout, report)
				}
				fmt.Fprintf(stdout, "Total: %d  Valid: %d  Malformed: %d\n",
					report.Total, report.SchemaValid, len(report.Malformed))
				fmt.Fprintf(stdout, "Age: <30d=%d  30-90d=%d  >90d=%d\n",
					report.ByAge.Under30, report.ByAge.From30To90, report.ByAge.Over90)
				return nil
			}

			f := snapshotquery.Filter{Now: nowTime}
			if olderThan != "" {
				d, err := time.ParseDuration(olderThan)
				if err != nil {
					return &ui.UserError{Err: fmt.Errorf("parse --older-than: %w", err)}
				}
				f.OlderThan = d
			}
			if newerThan != "" {
				d, err := time.ParseDuration(newerThan)
				if err != nil {
					return &ui.UserError{Err: fmt.Errorf("parse --newer-than: %w", err)}
				}
				f.NewerThan = d
			}

			results, err := snapshotquery.Query(dir, f)
			if err != nil {
				return fmt.Errorf("snapshot query: %w", err)
			}

			if format == "json" {
				return jsonutil.WriteIndented(stdout, results)
			}

			if len(results) == 0 {
				fmt.Fprintln(stdout, "No matching snapshots found.")
				return nil
			}
			for _, s := range results {
				fmt.Fprintf(stdout, "%-40s  %s  %.0fd  %d assets\n",
					filepath.Base(s.Path), s.CapturedAt.Format(time.RFC3339), s.AgeDays, s.AssetCount)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&dir, "dir", "observations", "Observation snapshots directory")
	cmd.Flags().StringVar(&olderThan, "older-than", "", "Filter to snapshots older than duration (e.g. 720h)")
	cmd.Flags().StringVar(&newerThan, "newer-than", "", "Filter to snapshots newer than duration (e.g. 48h)")
	cmd.Flags().BoolVar(&health, "health", false, "Produce archive health summary")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().StringVar(&now, "now", "", "Override current time (RFC3339) for deterministic output")

	return cmd
}

func assignCommandGroup(root *cobra.Command, use, groupID string) {
	cmd, _, err := root.Find([]string{use})
	if err != nil || cmd == nil {
		return
	}
	cmd.GroupID = groupID
}
