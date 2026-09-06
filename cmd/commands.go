package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/apply"
	applylint "github.com/sufield/stave/cmd/apply/lint"
	applyverify "github.com/sufield/stave/cmd/apply/verify"
	staveattest "github.com/sufield/stave/cmd/attest"
	stavebisect "github.com/sufield/stave/cmd/bisect"
	stavebundle "github.com/sufield/stave/cmd/bundle"
	catalog "github.com/sufield/stave/cmd/catalog"
	stavecelcmd "github.com/sufield/stave/cmd/cel"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	stavecompare "github.com/sufield/stave/cmd/compare"
	stavecompliance "github.com/sufield/stave/cmd/compliance"
	contract "github.com/sufield/stave/cmd/contract"
	stavecoverage "github.com/sufield/stave/cmd/coverage"
	"github.com/sufield/stave/cmd/diagnose"
	diagreport "github.com/sufield/stave/cmd/diagnose/report"
	stavediscover "github.com/sufield/stave/cmd/discover"
	"github.com/sufield/stave/cmd/doctor"
	"github.com/sufield/stave/cmd/enforce"
	staveexempt "github.com/sufield/stave/cmd/exempt"
	"github.com/sufield/stave/cmd/expand"
	staveexport "github.com/sufield/stave/cmd/export"
	stavefeatures "github.com/sufield/stave/cmd/features"
	stavefingerprint "github.com/sufield/stave/cmd/fingerprint"
	staveforge "github.com/sufield/stave/cmd/forge"
	stavegaps "github.com/sufield/stave/cmd/gaps"
	staveiam "github.com/sufield/stave/cmd/iam"
	"github.com/sufield/stave/cmd/initcmd"
	initalias "github.com/sufield/stave/cmd/initcmd/alias"
	initconfig "github.com/sufield/stave/cmd/initcmd/config"
	"github.com/sufield/stave/cmd/inspect"
	stavemap "github.com/sufield/stave/cmd/map"
	stavemetrics "github.com/sufield/stave/cmd/metrics"
	stavenep "github.com/sufield/stave/cmd/nep"
	stavenetwork "github.com/sufield/stave/cmd/network"
	stavepack "github.com/sufield/stave/cmd/pack"
	stavepath "github.com/sufield/stave/cmd/path"
	staveplan "github.com/sufield/stave/cmd/plan"
	staveprofile "github.com/sufield/stave/cmd/profile"
	staveprove "github.com/sufield/stave/cmd/prove"
	stavereadiness "github.com/sufield/stave/cmd/readiness"
	staverecommend "github.com/sufield/stave/cmd/recommend"
	staverender "github.com/sufield/stave/cmd/render"
	stavereport "github.com/sufield/stave/cmd/report"
	stavesanitize "github.com/sufield/stave/cmd/sanitize"
	stavescore "github.com/sufield/stave/cmd/score"
	stavescorecard "github.com/sufield/stave/cmd/scorecard"
	search "github.com/sufield/stave/cmd/search"
	staveservices "github.com/sufield/stave/cmd/services"
	stavesnapshotdiff "github.com/sufield/stave/cmd/snapshotdiff"
	stavetelemetry "github.com/sufield/stave/cmd/telemetry"
	"github.com/sufield/stave/cmd/templatecmd"
	templateeject "github.com/sufield/stave/cmd/templatecmd/ejectcmd"
	templateinit "github.com/sufield/stave/cmd/templatecmd/initcmd"
	templatenew "github.com/sufield/stave/cmd/templatecmd/newcmd"
	templateverify "github.com/sufield/stave/cmd/templatecmd/verifycmd"
	stavetest "github.com/sufield/stave/cmd/test"
	stavetoolmap "github.com/sufield/stave/cmd/toolmap"
	stavetransform "github.com/sufield/stave/cmd/transform"
	stavetrend "github.com/sufield/stave/cmd/trend"
	validatemapping "github.com/sufield/stave/cmd/validatemapping"
	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	infrareport "github.com/sufield/stave/internal/adapters/report"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/core/reporting"
	"github.com/sufield/stave/internal/platform/fsutil"
)

const (
	groupEvaluate   = "evaluate"
	groupData       = "data"
	groupControls   = "controls"
	groupCompliance = "compliance"
	groupArtifacts  = "artifacts"
	groupAnalysis   = "analysis"
	groupSetup      = "setup"
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

	// Getting started
	root.AddCommand(initcmd.NewGenerateCmd())

	// Control Engine
	root.AddCommand(applylint.NewCmd(ui.DefaultRuntime()))
	root.AddCommand(apply.NewApplyCmd())
	root.AddCommand(applyverify.NewCmd(ui.DefaultRuntime()))
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
	root.AddCommand(expand.NewCmd())

	// Workflow & CI
	root.AddCommand(enforce.NewStatusCmd())

	snapshotCmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Snapshot inspection commands",
		Long:  "Grouped snapshot commands: diff, compare." + OfflineHelpSuffix,
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

	// Capability scope
	root.AddCommand(stavefeatures.NewCmd())

	// Policy fingerprint diagnostics
	root.AddCommand(stavefingerprint.NewCmd())

	// Export & Interop
	root.AddCommand(stavecompliance.NewCmd())
	root.AddCommand(stavepack.NewCmd())
	root.AddCommand(stavediscover.NewCmd())
	root.AddCommand(staveplan.NewCmd())
	root.AddCommand(stavetransform.NewCmd())
	root.AddCommand(staveexport.NewCmd())

	// Data & Artifacts
	root.AddCommand(enforce.NewGenerateCmd())
	root.AddCommand(newControlsCmd(f.NewCtlRepo))

	// Introspection
	root.AddCommand(inspect.NewInspectCmd())

	// Z3 SMT formal verification
	root.AddCommand(staveprove.NewCmd())

	// Network reachability analysis
	root.AddCommand(stavenetwork.NewCmd())

	// Net Effective Permissions (CIEM)
	root.AddCommand(stavenep.NewCmd())

	// IAM policy analysis (composition spine — iam-explain bridge)
	root.AddCommand(staveiam.NewCmd())

	// CEL expression tools
	root.AddCommand(stavecelcmd.NewCmd())

	// Security chronology
	root.AddCommand(stavebisect.NewCmd())

	// Evidence bundling
	root.AddCommand(stavebundle.NewCmd())

	// Snapshot attestation
	root.AddCommand(staveattest.NewCmd())

	// Control authoring
	root.AddCommand(staveforge.NewCmd())

	// Posture trending
	root.AddCommand(stavetrend.NewCmd())

	// Risk acceptance management
	root.AddCommand(staveexempt.NewCmd())

	// ATT&CK coverage map, with offensive tool prerequisite mapping
	// (stave map attack) as a subcommand.
	root.AddCommand(newMapCmd())

	// Field coverage analysis
	root.AddCommand(stavecoverage.NewCmd())

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
	// mapping directory into one agent-facing view. `schemas` (the
	// wire-format contract listing) is wired as a subcommand since
	// it shares the same "input contract" vocabulary.
	contractCmd := contract.NewCmd()
	contractCmd.AddCommand(newSchemasCmd())
	root.AddCommand(contractCmd)

	// Steampipe→Stave mapping validation. Lets an agent confirm a
	// generated contracts/steampipe/*.yaml is well-formed, references
	// only declared schema paths, and covers the catalog's read
	// surface for that asset type before it ships an observation.
	root.AddCommand(validatemapping.NewCmd())

	// User-facing catalog: grouped detections + chains + operational
	// features. Also registered under `capabilities catalog` below
	// for backward compatibility (each registration is a separate
	// Command instance — Cobra cannot share).
	root.AddCommand(catalog.NewCmd())

	// Service registry — tracks the AWS service universe and
	// Stave's coverage. Hidden; internal development tooling.
	root.AddCommand(staveservices.NewCmd())

	// Free-form search across controls + chains + asset types.
	// Bridges user intent ("public S3 bucket") to catalog vocabulary
	// without forcing the user to know the taxonomy first.
	root.AddCommand(search.NewCmd())

	// Multi-framework scorecard
	root.AddCommand(stavescorecard.NewCmd())

	// Standalone sanitization
	root.AddCommand(stavesanitize.NewCmd())

	// Template rendering (JSON data + Go template = output)
	root.AddCommand(staverender.NewCmd())

	// Prometheus metrics export
	root.AddCommand(stavemetrics.NewCmd())

	// Profile management
	root.AddCommand(staveprofile.NewCmd())

	// Compliance gap analysis
	root.AddCommand(stavecompare.NewCmd())

	// Executive report
	root.AddCommand(stavereport.NewCmd())

	// Posture score
	root.AddCommand(stavescore.NewCmd())

	// Assessment templates
	root.AddCommand(staverecommend.NewCmd())
	templateCmd := templatecmd.NewCmd()
	templateCmd.AddCommand(templateinit.NewCmd())
	templateCmd.AddCommand(templatenew.NewCmd())
	templateCmd.AddCommand(templateverify.NewCmd())
	templateCmd.AddCommand(templateeject.NewCmd())
	root.AddCommand(templateCmd)

	// Telemetry bridge
	root.AddCommand(stavetelemetry.NewCmd())

	// Supportability
	root.AddCommand(doctor.NewCmd())
	graphCmd := enforce.NewGraphCmd()
	pathCmd := stavepath.NewCmd()
	pathCmd.Use = "path"
	graphCmd.AddCommand(pathCmd)
	root.AddCommand(graphCmd)
	root.AddCommand(initalias.NewCmd(root))
	{
		capabilitiesCmd := newCapabilitiesCmd()
		capabilitiesCmd.AddCommand(catalog.NewCmd())
		root.AddCommand(capabilitiesCmd)
	}
	root.AddCommand(newCompletionCmd())
	root.AddCommand(newVersionCmd(app.Edition))

	// Settings
	root.AddCommand(initconfig.NewConfigCmd(ui.DefaultRuntime()))
	return nil
}

// newMapCmd builds the ATT&CK coverage map command, with offensive tool
// prerequisite mapping (stave map attack) wired as a subcommand.
func newMapCmd() *cobra.Command {
	mapCmd := stavemap.NewCmd()
	toolmapCmd := stavetoolmap.NewCmd()
	toolmapCmd.Use = "attack"
	toolmapCmd.Short = "Map offensive tools to configuration prerequisites and find coverage gaps"
	mapCmd.AddCommand(toolmapCmd)
	return mapCmd
}

func wireSnapshotSubtree(snapshotCmd *cobra.Command) {
	snapshotCmd.AddCommand(enforce.NewDiffCmd())

	snapshotCompareCmd := stavesnapshotdiff.NewCmd()
	snapshotCompareCmd.Use = "compare"
	snapshotCompareCmd.Short = "Compare two explicit snapshot files"
	snapshotCmd.AddCommand(snapshotCompareCmd)
}

func wireCISubtree(ciCmd *cobra.Command) {
	ciCmd.AddCommand(enforce.NewBaselineCmd())
	// Gate adapters (FindingsCounter, BaselineComparer, OverdueCounter)
	// are now wired internally by pkg/stave.Gate; fix / fix-loop wire
	// their own adapters through pkg/stave too — the CI subcommands no
	// longer accept dependency injection at this boundary.
	ciCmd.AddCommand(enforce.NewGateCmd())
	ciCmd.AddCommand(enforce.NewFixLoopCmd())
	ciCmd.AddCommand(enforce.NewCiDiffCmd())
	ciCmd.AddCommand(enforce.NewFixCmd())
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
