// Package profile implements the 'stave profile' command group for
// compliance profile management.
package profile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	evidenceadapter "github.com/sufield/stave/internal/adapters/evidence"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// NewCmd constructs the profile command group.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage compliance profiles",
		Long: `Create, list, and validate custom compliance profile files.

Subcommands:
  list       Show built-in and custom profiles
  validate   Validate a profile file
  create     Generate a starter profile YAML

Exit Codes:
  0   Success
  1   Validation errors
  2   Invalid input`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// list
	var profilesDir string
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List available compliance profiles",
		Long: `Show all built-in profiles and any custom profiles found in the
specified directory.

Exit Codes:
  0   Profiles listed`,
		Example:       `  stave profile list --profiles-dir ./profiles/`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runList(cmd.OutOrStdout(), profilesDir)
		},
	}
	listCmd.Flags().StringVar(&profilesDir, "profiles-dir", "", "directory of custom profile YAML files")
	cmd.AddCommand(listCmd)

	// validate
	var validateFile string
	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a profile file",
		Long: `Check a custom compliance profile YAML for correctness: required
fields present, referenced control IDs exist in the catalog.

Exit Codes:
  0   Valid
  1   Errors found
  2   Invalid input`,
		Example:       `  stave profile validate --file profiles/my-policy.yaml`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runValidate(cmd.OutOrStdout(), validateFile)
		},
	}
	validateCmd.Flags().StringVar(&validateFile, "file", "", "profile YAML file (required)")
	_ = validateCmd.MarkFlagRequired("file")
	cmd.AddCommand(validateCmd)

	// create
	var createName, createDesc, createOut string
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Generate a starter profile YAML",
		Long: `Generate a starter custom compliance profile YAML file. Edit the
generated file to add sections and control requirements.

Exit Codes:
  0   Profile created
  2   Invalid input`,
		Example:       `  stave profile create --name "acme-internal" --out profiles/acme.yaml`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCreate(cmd.ErrOrStderr(), createName, createDesc, createOut)
		},
	}
	createCmd.Flags().StringVar(&createName, "name", "", "profile name (required)")
	createCmd.Flags().StringVar(&createDesc, "description", "", "profile description")
	createCmd.Flags().StringVar(&createOut, "out", "", "output file path (required)")
	_ = createCmd.MarkFlagRequired("name")
	_ = createCmd.MarkFlagRequired("out")
	cmd.AddCommand(createCmd)

	return cmd
}

func runList(w io.Writer, profilesDir string) error {
	fmt.Fprintln(w, "AVAILABLE PROFILES")
	fmt.Fprintln(w)

	builtIn, err := evidenceadapter.LoadEmbeddedProfiles()
	if err == nil && len(builtIn) > 0 {
		fmt.Fprintf(w, "Built-in (%d):\n", len(builtIn))
		for _, p := range builtIn {
			fmt.Fprintf(w, "  %-20s %s\n", p.ID, p.Name)
		}
	}

	if profilesDir != "" {
		entries, readErr := os.ReadDir(profilesDir)
		if readErr == nil {
			var custom []string
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
					custom = append(custom, e.Name())
				}
			}
			if len(custom) > 0 {
				fmt.Fprintf(w, "\nCustom (%d, from %s):\n", len(custom), profilesDir)
				for _, name := range custom {
					fmt.Fprintf(w, "  %s\n", strings.TrimSuffix(name, ".yaml"))
				}
			}
		}
	}

	return nil
}

func runValidate(w io.Writer, file string) error {
	profile, err := evidenceadapter.LoadProfileFromFile(file)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load profile: %w", err)}
	}

	fmt.Fprintf(w, "OK %s is valid\n\n", file)
	fmt.Fprintf(w, "  ID:           %s\n", profile.ID)
	fmt.Fprintf(w, "  Name:         %s\n", profile.Name)
	fmt.Fprintf(w, "  Requirements: %d\n", len(profile.Requirements))

	// Count total controls.
	totalControls := 0
	for _, req := range profile.Requirements {
		totalControls += len(req.ControlIDs)
	}
	fmt.Fprintf(w, "  Controls:     %d\n", totalControls)

	return nil
}

func runCreate(stderr io.Writer, name, desc, outPath string) error {
	if desc == "" {
		desc = name + " compliance profile"
	}

	content := fmt.Sprintf(`schema_version: "1"
id: %s
name: "%s"
description: >
  %s

sections:
  - id: "section-1"
    title: "Add section title here"
    required_controls:
      - control_id: CTL.S3.PUBLIC.001
        rationale: "Add rationale here"
`, strings.ReplaceAll(name, " ", "-"), name, desc)

	if err := fsutil.SafeWriteFile(outPath, []byte(content), fsutil.WriteOptions{Perm: 0o644}); err != nil {
		return fmt.Errorf("write profile: %w", err)
	}

	fmt.Fprintf(stderr, "Wrote %s\nEdit to add sections and controls.\nValidate with: stave profile validate --file %s\n",
		outPath, filepath.Base(outPath))
	return nil
}
