package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/apply/extractor"
	"github.com/sufield/stave/cmd/bugreport"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/cmd/diagnose"
	"github.com/sufield/stave/cmd/diagnose/artifacts"
	diagdocs "github.com/sufield/stave/cmd/diagnose/docs"
	"github.com/sufield/stave/cmd/doctor"
	"github.com/sufield/stave/cmd/enforce"
	initalias "github.com/sufield/stave/cmd/initcmd/alias"
	"github.com/sufield/stave/cmd/securityaudit"
	"github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// groupDevTools is the help group for developer-only commands.
const groupDevTools = "dev-tools"

type versionOutput struct {
	Version           string        `json:"version"`
	Edition           string        `json:"edition"`
	SchemaControl     kernel.Schema `json:"schema_control"`
	SchemaObservation kernel.Schema `json:"schema_observation"`
	SchemaOutput      kernel.Schema `json:"schema_output"`
	ProjectRoot       string        `json:"project_root,omitempty"`
	LockFile          string        `json:"lock_file,omitempty"`
	LockHash          string        `json:"lock_hash,omitempty"`
	LockPresent       bool          `json:"lock_present"`
}

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

func newVersionCmd(edition string) *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long:  "Version prints binary version and, with --verbose, schema and lockfile status." + OfflineHelpSuffix,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := versionOutput{
				Version:           GetVersion(),
				Edition:           edition,
				SchemaControl:     kernel.SchemaControl,
				SchemaObservation: kernel.SchemaObservation,
				SchemaOutput:      kernel.SchemaOutput,
			}
			if verbose {
				if resolver, resolverErr := projctx.NewResolver(); resolverErr == nil {
					root, err := resolver.DetectProjectRoot(".")
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
			}
			if cmdutil.GetGlobalFlags(cmd).IsJSONMode() {
				return jsonutil.WriteIndented(cmd.OutOrStdout(), out)
			}
			if !verbose {
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s (%s)\n", out.Version, out.Edition)
				return err
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(),
				"Version: %s\nEdition: %s\nSchemas: control=%s observation=%s output=%s\nProject root: %s\nLockfile: %v (%s)\nLock hash: %s\n",
				out.Version, out.Edition, out.SchemaControl, out.SchemaObservation, out.SchemaOutput,
				compose.EmptyDash(out.ProjectRoot), out.LockPresent, compose.EmptyDash(out.LockFile), compose.EmptyDash(out.LockHash))
			return err
		},
	}

	cmd.Flags().BoolVar(&verbose, "verbose", false, "Include schema and lockfile status")

	return cmd
}

// WireDevCommands attaches developer-only commands to an already prod-wired App.
func WireDevCommands(app *App) {
	root := app.Root

	// Getting started (dev additions)
	root.AddCommand(doctor.NewCmd())

	// Control Engine (dev additions)
	root.AddCommand(extractor.NewCmd(ui.DefaultRuntime()))
	root.AddCommand(diagnose.NewTraceCmd())
	root.AddCommand(artifacts.NewLintCmd())
	root.AddCommand(artifacts.NewFmtCmd())

	// Workflow (dev additions)
	root.AddCommand(securityaudit.NewCmd())

	// Data & Artifacts (dev additions)
	root.AddCommand(artifacts.NewControlsCmd())
	root.AddCommand(artifacts.NewPacksCmd())
	root.AddCommand(enforce.NewGraphCmd())

	// Utilities (dev additions)
	docsCmd := &cobra.Command{
		Use:   "docs",
		Short: "Documentation workflow commands",
		Long:  "Grouped docs commands: search, open." + OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}
	root.AddCommand(docsCmd)
	wireDocsSubtree(docsCmd)

	root.AddCommand(bugreport.NewCmd())
	root.AddCommand(initalias.NewCmd(root))
	root.AddCommand(diagnose.NewPromptCmd())

	// Meta commands (schemas, capabilities, version subcommand)
	root.AddCommand(newCapabilitiesCmd(), newSchemasCmd(), newVersionCmd(app.Edition))
}

func wireDocsSubtree(docsCmd *cobra.Command) {
	docsCmd.AddCommand(diagdocs.NewDocsSearchCmd())
	docsCmd.AddCommand(diagdocs.NewDocsOpenCmd())
}

// runCapabilities executes the capabilities command.
func runCapabilities(cmd *cobra.Command, _ []string) error {
	caps := capabilities.GetCapabilities(GetVersion())

	if err := jsonutil.WriteIndented(cmd.OutOrStdout(), caps); err != nil {
		return fmt.Errorf("failed to encode capabilities: %w", err)
	}
	return nil
}
