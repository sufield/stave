package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// ---------------------------------------------------------------------------
// VersionRunner — extracted orchestrator for the version command
// ---------------------------------------------------------------------------

// VersionRunner collects version, schema, and project metadata for display.
type VersionRunner struct {
	Stdout io.Writer
	Flags  cmdutil.GlobalFlags
}

// Run produces version output in text or JSON format.
func (r *VersionRunner) Run(edition Edition, verbose bool) error {
	out := versionOutput{
		Version:           GetVersion(),
		Edition:           string(edition),
		SchemaControl:     kernel.SchemaControl,
		SchemaObservation: kernel.SchemaObservation,
		SchemaOutput:      kernel.SchemaOutput,
	}

	if verbose {
		r.enrichWithProjectInfo(&out)
	}

	if r.Flags.IsJSONMode() {
		return jsonutil.WriteIndented(r.Stdout, out)
	}

	if !verbose {
		_, err := fmt.Fprintf(r.Stdout, "%s (%s)\n", out.Version, out.Edition)
		return err
	}

	_, err := fmt.Fprintf(r.Stdout,
		"Version:      %s\nEdition:      %s\nSchemas:      control=%s, observation=%s, output=%s\nProject root: %s\nLockfile:     %v (%s)\nLock hash:    %s\n",
		out.Version, out.Edition, out.SchemaControl, out.SchemaObservation, out.SchemaOutput,
		compose.EmptyDash(out.ProjectRoot), out.LockPresent, compose.EmptyDash(out.LockFile), compose.EmptyDash(out.LockHash))
	return err
}

// enrichWithProjectInfo detects the project root and reads lockfile metadata.
func (r *VersionRunner) enrichWithProjectInfo(out *versionOutput) {
	resolver, err := projctx.NewResolver()
	if err != nil {
		return
	}
	root, err := resolver.DetectProjectRoot(".")
	if err != nil {
		return
	}
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

// ---------------------------------------------------------------------------
// Command constructors
// ---------------------------------------------------------------------------

func newVersionCmd(edition Edition) *cobra.Command {
	var verbose bool
	cmd := &cobra.Command{
		Use:           "version",
		Short:         "Print version and environment state",
		Long:          "Version prints binary version and, with --verbose, schema and lockfile status." + OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runner := &VersionRunner{
				Stdout: cmd.OutOrStdout(),
				Flags:  cmdutil.GetGlobalFlags(cmd),
			}
			return runner.Run(edition, verbose)
		},
	}
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Include schema and lockfile status")
	return cmd
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
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			caps := capabilities.GetCapabilities(GetVersion())
			return jsonutil.WriteIndented(cmd.OutOrStdout(), caps)
		},
	}
}

// versionOutput represents the structured metadata for the binary.
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
