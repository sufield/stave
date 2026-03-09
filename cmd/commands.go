package cmd

import (
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
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
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

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

const (
	groupGettingStarted = "getting-started"
	groupCore           = "core-evaluation"
	groupWorkflow       = "workflow"
	groupArtifacts      = "artifacts"
	groupUtilities      = "utilities"
)

func newCapabilitiesCmd() *cobra.Command {
	return &cobra.Command{
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
}

func newVersionCmd() *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
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
			if verbose {
				root, err := projctx.DetectProjectRoot(".")
				if err == nil {
					out.ProjectRoot = root
					lockPath := filepath.Join(root, CLILockfile)
					if _, statErr := os.Stat(lockPath); statErr == nil {
						out.LockPresent = true
						out.LockFile = lockPath
						if data, readErr := fsutil.ReadFileLimited(lockPath); readErr == nil {
							sum := sha256.Sum256(data)
							out.LockHash = hex.EncodeToString(sum[:])
						}
					}
				}
			}
			if cmdutil.IsJSONMode(cmd) {
				return jsonutil.WriteIndented(cmd.OutOrStdout(), out)
			}
			if !verbose {
				_, err := fmt.Fprintln(cmd.OutOrStdout(), out.Version)
				return err
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(),
				"Version: %s\nSchemas: control=%s observation=%s output=%s\nProject root: %s\nLockfile: %v (%s)\nLock hash: %s\n",
				out.Version, out.SchemaControl, out.SchemaObservation, out.SchemaOutput,
				compose.EmptyDash(out.ProjectRoot), out.LockPresent, compose.EmptyDash(out.LockFile), compose.EmptyDash(out.LockHash))
			return err
		},
	}

	cmd.Flags().BoolVar(&verbose, "verbose", false, "Include schema and lockfile status")

	return cmd
}

// WireMetaCommands attaches root metadata/introspection commands.
func WireMetaCommands(root *cobra.Command) {
	root.AddCommand(newCapabilitiesCmd(), newSchemasCmd(), newVersionCmd())
}

// WireCommands attaches the full command tree to the root command.
func WireCommands(root *cobra.Command) {
	// Getting started
	root.AddCommand(initcmd.NewInitCmd())
	root.AddCommand(initcmd.NewQuickstartCmd())
	root.AddCommand(initcmd.NewDemoCmd())
	root.AddCommand(initcmd.NewGenerateCmd())
	root.AddCommand(doctor.NewCmd())

	// Core evaluation
	root.AddCommand(applyvalidate.NewCmd(nil))
	root.AddCommand(apply.NewPlanCmd())
	root.AddCommand(apply.NewApplyCmd())
	root.AddCommand(applyverify.NewCmd(nil))
	root.AddCommand(extractor.NewCmd(nil))
	root.AddCommand(diagnose.NewDiagnoseCmd())
	root.AddCommand(diagnose.NewExplainCmd())
	root.AddCommand(diagnose.NewTraceCmd())
	root.AddCommand(artifacts.NewLintCmd())
	root.AddCommand(artifacts.NewFmtCmd())

	// Workflow & CI
	root.AddCommand(enforce.NewStatusCmd())
	root.AddCommand(contextcmd.NewContextCmd())
	root.AddCommand(securityaudit.NewCmd())

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
		Long:  "Grouped CI/CD commands: baseline, gate, fix-loop, diff." + OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}
	root.AddCommand(ciCmd)
	wireCISubtree(ciCmd)

	// Data & Artifacts
	root.AddCommand(ingest.NewIngestCmd(nil))
	root.AddCommand(artifacts.NewControlsCmd())
	root.AddCommand(artifacts.NewPacksCmd())
	root.AddCommand(enforce.NewEnforceCmd())
	root.AddCommand(enforce.NewGraphCmd())
	root.AddCommand(diagreport.NewReportCmd())

	// Utilities
	docsCmd := &cobra.Command{
		Use:   "docs",
		Short: "Documentation workflow commands",
		Long:  "Grouped docs commands: search, open." + OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}
	root.AddCommand(docsCmd)
	wireDocsSubtree(docsCmd)

	root.AddCommand(bugreport.NewCmd())
	root.AddCommand(initconfig.NewConfigCmd(ui.NewRuntime(nil, nil)))
	root.AddCommand(initalias.NewAliasCmd(root))
	root.AddCommand(initenv.NewEnvCmd())
	root.AddCommand(diagnose.NewPromptCmd())
	root.AddCommand(enforce.NewFixCmd())
}

func wireSnapshotSubtree(snapshotCmd *cobra.Command) {
	snapshotCmd.AddCommand(enforce.NewDiffCmd())
	for _, subCmd := range prune.Commands() {
		snapshotCmd.AddCommand(subCmd)
	}
	snapshotCmd.AddCommand(manifest.NewCmd())
}

func wireCISubtree(ciCmd *cobra.Command) {
	ciCmd.AddCommand(enforce.NewBaselineCmd())
	ciCmd.AddCommand(enforce.NewGateCmd())
	ciCmd.AddCommand(enforce.NewFixLoopCmd())
	ciCmd.AddCommand(enforce.NewCiDiffCmd())
}

func wireDocsSubtree(docsCmd *cobra.Command) {
	docsCmd.AddCommand(diagdocs.NewDocsSearchCmd())
	docsCmd.AddCommand(diagdocs.NewDocsOpenCmd())
}

// runCapabilities executes the capabilities command.
// It retrieves the application's capabilities and outputs them as formatted JSON to stdout.
func runCapabilities(cmd *cobra.Command, _ []string) error {
	caps := capabilities.GetCapabilities(GetVersion())

	if err := jsonutil.WriteIndented(cmd.OutOrStdout(), caps); err != nil {
		return fmt.Errorf("failed to encode capabilities: %w", err)
	}
	return nil
}

func assignCommandGroup(root *cobra.Command, use, groupID string) {
	cmd, _, err := root.Find([]string{use})
	if err != nil || cmd == nil {
		return
	}
	cmd.GroupID = groupID
}
