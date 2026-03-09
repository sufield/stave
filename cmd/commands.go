package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/apply"
	"github.com/sufield/stave/cmd/apply/extractor"
	applyvalidate "github.com/sufield/stave/cmd/apply/validate"
	applyverify "github.com/sufield/stave/cmd/apply/verify"
	"github.com/sufield/stave/cmd/bugreport"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/diagnose"
	"github.com/sufield/stave/cmd/diagnose/artifacts"
	diagdocs "github.com/sufield/stave/cmd/diagnose/docs"
	diagreport "github.com/sufield/stave/cmd/diagnose/report"
	"github.com/sufield/stave/cmd/doctor"
	"github.com/sufield/stave/cmd/enforce"
	"github.com/sufield/stave/cmd/ingest"
	"github.com/sufield/stave/cmd/initcmd"
	initalias "github.com/sufield/stave/cmd/initcmd/alias"
	initconfig "github.com/sufield/stave/cmd/initcmd/config"
	"github.com/sufield/stave/cmd/initcmd/contextcmd"
	initenv "github.com/sufield/stave/cmd/initcmd/env"
	"github.com/sufield/stave/cmd/prune"
	"github.com/sufield/stave/cmd/prune/manifest"
	"github.com/sufield/stave/cmd/securityaudit"
	"github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/kernel"
)

var capabilitiesCmd = &cobra.Command{
	Use:   "capabilities",
	Short: "Print supported input types and version constraints",
	Long: `Capabilities outputs a JSON document describing what observation schemas,
control DSL versions, input source types, and command capability metadata
this version of Stave supports.

Exit Codes:
  0   - Success
  4   - Internal error

Examples:
  # Check supported versions
  stave capabilities

  # Pipe to jq for parsing
  stave capabilities | jq '.observations.schema_versions'

  # Check supported source types
  stave capabilities | jq '.inputs.source_types'

  # Check security-audit capabilities
  stave capabilities | jq '.security_audit'` + OfflineHelpSuffix,
	Args:          cobra.NoArgs,
	RunE:          runCapabilities,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var versionVerbose bool

type versionOutput struct {
	Version           string        `json:"version"`
	SchemaControl     kernel.Schema `json:"schema_control"`
	SchemaObservation kernel.Schema `json:"schema_observation"`
	SchemaOutput      kernel.Schema `json:"schema_output"`
	ProjectRoot       string        `json:"project_root,omitempty"`
	LockFile          string        `json:"lock_file,omitempty"`
	LockHash          string        `json:"lock_hash,omitempty"`
	LockPresent       bool          `json:"lock_present"`
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  "Version prints binary version and, with --verbose, schema and lockfile status." + OfflineHelpSuffix,
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		out := versionOutput{
			Version:           GetVersion(),
			SchemaControl:     kernel.SchemaControl,
			SchemaObservation: kernel.SchemaObservation,
			SchemaOutput:      kernel.SchemaOutput,
		}
		if versionVerbose {
			root, err := cmdutil.DetectProjectRoot(".")
			if err == nil {
				out.ProjectRoot = root
				lockPath := filepath.Join(root, CLILockfile)
				if _, statErr := os.Stat(lockPath); statErr == nil {
					out.LockPresent = true
					out.LockFile = lockPath
					// #nosec G304 -- lockPath is derived from detected project root plus fixed lockfile name.
					if data, readErr := os.ReadFile(lockPath); readErr == nil {
						sum := sha256.Sum256(data)
						out.LockHash = hex.EncodeToString(sum[:])
					}
				}
			}
		}
		if IsJSONMode() {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		}
		if !versionVerbose {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), out.Version)
			return err
		}
		_, err := fmt.Fprintf(cmd.OutOrStdout(),
			"Version: %s\nSchemas: control=%s observation=%s output=%s\nProject root: %s\nLockfile: %v (%s)\nLock hash: %s\n",
			out.Version, out.SchemaControl, out.SchemaObservation, out.SchemaOutput,
			cmdutil.EmptyDash(out.ProjectRoot), out.LockPresent, cmdutil.EmptyDash(out.LockFile), cmdutil.EmptyDash(out.LockHash))
		return err
	},
}

var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Snapshot lifecycle commands",
	Long:  "Grouped snapshot lifecycle commands: cleanup, archive, upcoming, quality, plan, hygiene, diff, manifest." + OfflineHelpSuffix,
	Args:  cobra.NoArgs,
}

var ciCmd = &cobra.Command{
	Use:   "ci",
	Short: "CI/CD policy and baseline commands",
	Long:  "Grouped CI/CD commands: baseline, gate, fix-loop, diff." + OfflineHelpSuffix,
	Args:  cobra.NoArgs,
}

var docsCmd = &cobra.Command{
	Use:   "docs",
	Short: "Documentation workflow commands",
	Long:  "Grouped docs commands: search, open." + OfflineHelpSuffix,
	Args:  cobra.NoArgs,
}

const (
	groupGettingStarted = "getting-started"
	groupCore           = "core-evaluation"
	groupWorkflow       = "workflow"
	groupArtifacts      = "artifacts"
	groupUtilities      = "utilities"
)

func init() {
	WireMetaCommands(RootCmd)
	WireCommands(RootCmd)
}

// WireMetaCommands attaches root metadata/introspection commands.
func WireMetaCommands(root *cobra.Command) {
	versionCmd.Flags().BoolVar(&versionVerbose, "verbose", false, "Include schema and lockfile status")
	root.AddCommand(capabilitiesCmd, schemasCmd, versionCmd)
}

// WireCommands attaches the full command tree to the root command.
func WireCommands(root *cobra.Command) {
	// Wire sub-package RootCmd references for tests that exercise the full command tree.
	initalias.SetRootCmd(root)

	// Getting started
	root.AddCommand(initcmd.InitCmd)
	root.AddCommand(initcmd.QuickstartCmd)
	root.AddCommand(initcmd.DemoCmd)
	root.AddCommand(initcmd.GenerateCmd)
	root.AddCommand(doctor.Cmd)

	// Core evaluation
	root.AddCommand(applyvalidate.ValidateCmd)
	root.AddCommand(apply.NewPlanCmd())
	root.AddCommand(apply.NewApplyCmd())
	root.AddCommand(applyverify.VerifyCmd)
	root.AddCommand(extractor.ExtractorCmd)
	root.AddCommand(diagnose.NewDiagnoseCmd())
	root.AddCommand(diagnose.NewExplainCmd())
	root.AddCommand(diagnose.NewTraceCmd())
	root.AddCommand(artifacts.LintCmd)
	root.AddCommand(artifacts.FmtCmd)

	// Workflow & CI
	root.AddCommand(enforce.StatusCmd)
	root.AddCommand(contextcmd.ContextCmd)
	root.AddCommand(securityaudit.Cmd)
	root.AddCommand(snapshotCmd)
	root.AddCommand(ciCmd)

	// Data & Artifacts
	root.AddCommand(ingest.IngestCmd)
	root.AddCommand(artifacts.ControlsCmd)
	root.AddCommand(artifacts.PacksCmd)
	root.AddCommand(enforce.EnforceCmd)
	root.AddCommand(enforce.GraphCmd)
	root.AddCommand(diagreport.ReportCmd)

	// Utilities
	root.AddCommand(docsCmd)
	root.AddCommand(bugreport.Cmd)
	root.AddCommand(initconfig.NewConfigCmd(ui.NewRuntime(nil, nil)))
	root.AddCommand(initalias.AliasCmd)
	root.AddCommand(initenv.EnvCmd)
	root.AddCommand(diagnose.NewPromptCmd())
	root.AddCommand(enforce.FixCmd)

	wireSnapshotSubtree()
	wireCISubtree()
	wireDocsSubtree()
}

func wireSnapshotSubtree() {
	snapshotCmd.AddCommand(enforce.DiffCmd)
	for _, subCmd := range prune.Commands {
		snapshotCmd.AddCommand(subCmd)
	}
	snapshotCmd.AddCommand(manifest.Cmd)
}

func wireCISubtree() {
	ciCmd.AddCommand(enforce.BaselineCmd)
	ciCmd.AddCommand(enforce.GateCmd)
	ciCmd.AddCommand(enforce.FixLoopCmd)
	ciCmd.AddCommand(enforce.CiDiffCmd)
}

func wireDocsSubtree() {
	docsCmd.AddCommand(diagdocs.DocsSearchCmd)
	docsCmd.AddCommand(diagdocs.DocsOpenCmd)
}

// runCapabilities executes the capabilities command.
// It retrieves the application's capabilities and outputs them as formatted JSON to stdout.
func runCapabilities(cmd *cobra.Command, _ []string) error {
	caps := capabilities.GetCapabilities(GetVersion())

	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(caps); err != nil {
		return fmt.Errorf("failed to encode capabilities: %w", err)
	}

	return nil
}

func assignRootCommandGroup(use, groupID string) {
	cmd, _, err := RootCmd.Find([]string{use})
	if err != nil || cmd == nil {
		return
	}
	cmd.GroupID = groupID
}
