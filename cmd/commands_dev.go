package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/controldata"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// ---------------------------------------------------------------------------
// VersionRunner — extracted orchestrator for the version command
// ---------------------------------------------------------------------------

// VersionRunner collects version, schema, and project metadata for display.
type VersionRunner struct {
	Stdout io.Writer
}

// Run produces version output in text or JSON format.
func (r *VersionRunner) Run(edition Edition, verbose, verify bool) error {
	out := versionOutput{
		Version:           Version(),
		Edition:           string(edition),
		SchemaControl:     kernel.SchemaControl,
		SchemaObservation: kernel.SchemaObservation,
		SchemaOutput:      kernel.SchemaOutput,
	}

	if verbose {
		r.enrichWithProjectInfo(&out)
	}

	if verify {
		r.enrichWithIntegrity(&out)
	}

	if !verbose && !verify {
		_, err := fmt.Fprintf(r.Stdout, "%s (%s)\n", out.Version, out.Edition)
		return err
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Version:      %s\nEdition:      %s\nSchemas:      control=%s, observation=%s, output=%s\n",
		out.Version, out.Edition, out.SchemaControl, out.SchemaObservation, out.SchemaOutput)

	if verbose {
		fmt.Fprintf(&sb, "Project root: %s\nLockfile:     %v (%s)\nLock hash:    %s\n",
			compose.EmptyDash(out.ProjectRoot), out.LockPresent, compose.EmptyDash(out.LockFile), compose.EmptyDash(out.LockHash))
	}

	if verify {
		fmt.Fprintf(&sb, "\nIntegrity:\n")
		fmt.Fprintf(&sb, "  Binary hash:  %s\n", compose.EmptyDash(out.BinaryHash))
		fmt.Fprintf(&sb, "  Policy hash:  %s\n", compose.EmptyDash(out.PolicyHash))
		fmt.Fprintf(&sb, "  Controls:     %d embedded\n", out.ControlCount)
		if out.GoVersion != "" {
			fmt.Fprintf(&sb, "  Go version:   %s\n", out.GoVersion)
		}
		if len(out.Modules) > 0 {
			fmt.Fprintf(&sb, "  Modules:      %d dependencies\n", len(out.Modules))
			for _, m := range out.Modules {
				fmt.Fprintf(&sb, "    %s\n", m)
			}
		}
	}

	_, err := fmt.Fprint(r.Stdout, sb.String())
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

// enrichWithIntegrity computes binary and policy library hashes for auditors.
func (r *VersionRunner) enrichWithIntegrity(out *versionOutput) {
	// Binary self-hash: sha256 of the running executable.
	if exe, err := os.Executable(); err == nil {
		if data, readErr := os.ReadFile(exe); readErr == nil { //nolint:gosec // reading own binary
			sum := sha256.Sum256(data)
			out.BinaryHash = "sha256:" + hex.EncodeToString(sum[:])
		}
	}

	// Policy library hash: sorted sha256 of all embedded control YAML files.
	var controlHashes []string
	err := fs.WalkDir(controldata.FS, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		if !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, readErr := fs.ReadFile(controldata.FS, path)
		if readErr != nil {
			return nil //nolint:nilerr // skip unreadable files
		}
		sum := sha256.Sum256(data)
		controlHashes = append(controlHashes, hex.EncodeToString(sum[:]))
		out.ControlCount++
		return nil
	})
	if err == nil && len(controlHashes) > 0 {
		sort.Strings(controlHashes)
		combined := sha256.Sum256([]byte(strings.Join(controlHashes, "\n")))
		out.PolicyHash = "sha256:" + hex.EncodeToString(combined[:])
	}

	// Go build info: version and module dependencies.
	if bi, ok := debug.ReadBuildInfo(); ok {
		out.GoVersion = bi.GoVersion
		for _, dep := range bi.Deps {
			out.Modules = append(out.Modules, dep.Path+"@"+dep.Version)
		}
	}
}

// ---------------------------------------------------------------------------
// Command constructors
// ---------------------------------------------------------------------------

func newVersionCmd(edition Edition) *cobra.Command {
	var verbose, verify, sbom bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version and environment state",
		Long: `Version prints binary version and, with --verbose, schema and lockfile status.
With --verify, prints integrity hashes for the binary, embedded policy library,
and Go module dependencies. Auditors compare these against known-good values.
With --sbom, outputs a CycloneDX JSON Software Bill of Materials.

Exit Codes:
  0   - Success
  4   - Internal error

Examples:
  stave version
  stave version --verbose
  stave version --verify
  stave version --sbom > stave-sbom.json` + OfflineHelpSuffix,
		Example:       `  stave version --verify`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if sbom {
				return writeSBOM(cmd.OutOrStdout(), edition)
			}
			runner := &VersionRunner{
				Stdout: cmd.OutOrStdout(),
			}
			return runner.Run(edition, verbose, verify)
		},
	}
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Include schema and lockfile status")
	cmd.Flags().BoolVar(&verify, "verify", false, "Print binary and policy library integrity hashes")
	cmd.Flags().BoolVar(&sbom, "sbom", false, "Output CycloneDX JSON Software Bill of Materials")
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
		Example:       `  stave capabilities | jq '.version'`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			caps := capabilities.Summarize(Version())
			return jsonutil.WriteIndented(cmd.OutOrStdout(), caps)
		},
	}
}

// writeSBOM generates a CycloneDX 1.5 JSON SBOM from Go build info.
func writeSBOM(w io.Writer, _ Edition) error {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return errors.New("build info unavailable (binary built without module support)")
	}

	type sbomComponent struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Purl    string `json:"purl,omitempty"`
	}

	type sbomTool struct {
		Vendor  string `json:"vendor"`
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	type sbomMetadata struct {
		Timestamp string     `json:"timestamp"`
		Tools     []sbomTool `json:"tools"`
		Component struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"component"`
	}

	type cyclonedx struct {
		BOMFormat   string          `json:"bomFormat"`
		SpecVersion string          `json:"specVersion"`
		Version     int             `json:"version"`
		Metadata    sbomMetadata    `json:"metadata"`
		Components  []sbomComponent `json:"components"`
	}

	components := make([]sbomComponent, 0, len(bi.Deps))
	for _, dep := range bi.Deps {
		components = append(components, sbomComponent{
			Type:    "library",
			Name:    dep.Path,
			Version: dep.Version,
			Purl:    "pkg:golang/" + dep.Path + "@" + dep.Version,
		})
	}

	doc := cyclonedx{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: sbomMetadata{
			Tools: []sbomTool{{
				Vendor:  "sufield",
				Name:    "stave",
				Version: Version(),
			}},
		},
		Components: components,
	}
	doc.Metadata.Component.Type = "application"
	doc.Metadata.Component.Name = "stave"
	doc.Metadata.Component.Version = Version()

	return jsonutil.WriteIndented(w, doc)
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

	// Integrity fields (populated by --verify).
	BinaryHash   string   `json:"binary_hash,omitempty"`
	PolicyHash   string   `json:"policy_hash,omitempty"`
	ControlCount int      `json:"control_count,omitempty"`
	GoVersion    string   `json:"go_version,omitempty"`
	Modules      []string `json:"modules,omitempty"`
}
