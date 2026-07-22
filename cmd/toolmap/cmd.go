// Package toolmap implements the 'stave toolmap' command for
// offensive tool prerequisite mapping and coverage gap analysis.
package toolmap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	yamlctl "github.com/sufield/stave/internal/adapters/controls/yaml"
	predalias "github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/app/toolmap"
	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
)

type options struct {
	ChainsDir   string
	ControlsDir string
	Format      string
	Generate    string
	Tool        string
	Capability  string
}

// NewCmd constructs the toolmap command.
func NewCmd() *cobra.Command {
	opts := &options{
		ChainsDir:   "chains",
		ControlsDir: "controls",
		Format:      "text",
	}

	cmd := &cobra.Command{
		Use:   "toolmap",
		Short: "Map offensive tools to configuration prerequisites and find coverage gaps",
		Long: `Perform a three-way join of chains × controls × offensive tool prerequisites.

For each registered tool, checks whether its configuration prerequisites are
detected by an existing chain (capability match) and validated by an existing
control (field path match). Prerequisites with both are "covered"; those
missing either are "gaps".

Inputs:
  --chains PATH       Path to chain definitions directory (default: chains)
  --controls PATH     Path to controls directory (default: controls)
  --format STRING     Output format: text (default) | json
  --generate PATH     Generate chain YAML skeletons for gaps into PATH
  --tool NAME         Show prerequisites for a specific tool
  --capability TOKEN  Show tools needing this capability

Exit Codes:
  0   Success
  2   Invalid input
  3   Gaps found
  4   Internal error`,
		Example: `  # Run three-way join, print gap report
  stave toolmap

  # JSON output for automation
  stave toolmap --format json

  # Generate chain skeletons for gaps
  stave toolmap --generate ./generated-chains

  # Show prerequisites for a specific tool
  stave toolmap --tool pacu

  # Show tools needing a capability
  stave toolmap --capability iam_credential_theft`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "chains", "path to chain definitions directory")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "path to controls directory")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().StringVar(&opts.Generate, "generate", "", "generate chain skeletons for gaps into this directory")
	cmd.Flags().StringVar(&opts.Tool, "tool", "", "show prerequisites for a specific tool")
	cmd.Flags().StringVar(&opts.Capability, "capability", "", "show tools needing this capability")

	return cmd
}

func run(w io.Writer, opts *options) error {
	if opts.Format != "text" && opts.Format != "json" {
		return &ui.UserError{Err: fmt.Errorf("unknown format %q (valid: text, json)", opts.Format)}
	}

	registry := toolmap.NewRegistry()

	if opts.Tool != "" {
		return showTool(w, registry, opts)
	}
	if opts.Capability != "" {
		return showCapability(w, registry, opts)
	}

	result, err := toolmap.Analyze(registry, opts.ChainsDir, loadControlsFromDisk, opts.ControlsDir)
	if err != nil {
		return fmt.Errorf("analyze: %w", err)
	}

	if opts.Generate != "" {
		n, genErr := toolmap.GenerateAll(result.Gaps, opts.Generate)
		if genErr != nil {
			return fmt.Errorf("generate: %w", genErr)
		}
		fmt.Fprintf(w, "Generated %d chain skeletons in %s\n", n, opts.Generate)
	}

	if opts.Format == "json" {
		return writeJSON(w, result)
	}
	return writeText(w, result)
}

func showTool(w io.Writer, registry *toolmap.Registry, opts *options) error {
	tool, ok := registry.Tool(opts.Tool)
	if !ok {
		return &ui.UserError{Err: fmt.Errorf("unknown tool %q", opts.Tool)}
	}

	if opts.Format == "json" {
		return writeJSON(w, tool)
	}

	fmt.Fprintf(w, "%s — %s\n", tool.Name, tool.Description)
	fmt.Fprintf(w, "Reference: %s\n\n", tool.Reference)
	fmt.Fprintf(w, "Prerequisites:\n")
	for _, p := range tool.Prerequisites {
		fmt.Fprintf(w, "  %-28s %s\n", p.Capability, p.FieldPath)
		fmt.Fprintf(w, "  %s%s\n\n", strings.Repeat(" ", 28), p.Rationale)
	}
	return nil
}

func showCapability(w io.Writer, registry *toolmap.Registry, opts *options) error {
	tools := registry.ToolsForCapability(opts.Capability)
	if len(tools) == 0 {
		fmt.Fprintf(w, "No tools require capability %q\n", opts.Capability)
		return nil
	}

	if opts.Format == "json" {
		return writeJSON(w, tools)
	}

	fmt.Fprintf(w, "Tools requiring %s:\n\n", opts.Capability)
	for _, t := range tools {
		fmt.Fprintf(w, "  %-20s %s\n", t.Name, t.Description)
	}
	return nil
}

func writeText(w io.Writer, result *toolmap.CoverageResult) error {
	fmt.Fprintf(w, "Coverage: %d covered, %d gaps\n\n", len(result.Covered), len(result.Gaps))

	if len(result.Gaps) > 0 {
		fmt.Fprintf(w, "GAPS:\n")
		for _, g := range result.Gaps {
			reason := "no chain, no control"
			if g.HasChain {
				reason = "no control"
			} else if g.HasControl {
				reason = "no chain"
			}
			fmt.Fprintf(w, "  %-20s %-28s %s (%s)\n", g.Tool, g.Capability, g.FieldPath, reason)
		}
		fmt.Fprintln(w)
	}

	if len(result.Covered) > 0 {
		fmt.Fprintf(w, "COVERED:\n")
		for _, c := range result.Covered {
			fmt.Fprintf(w, "  %-20s %-28s %s\n", c.Tool, c.Capability, c.FieldPath)
		}
	}

	if len(result.Gaps) > 0 {
		return ui.ErrViolationsFound
	}
	return nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func loadControlsFromDisk(rootDir string) ([]policy.ControlDefinition, error) {
	loader := yamlctl.NewControlLoader(yamlctl.WithAliasResolver(predalias.ResolverFunc()))
	var dirs []string
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && path != rootDir {
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", rootDir, err)
	}
	if len(dirs) == 0 {
		dirs = []string{rootDir}
	}

	var all []policy.ControlDefinition
	for _, d := range dirs {
		controls, loadErr := loader.LoadControls(context.Background(), d)
		if loadErr != nil {
			continue
		}
		all = append(all, controls...)
	}
	return all, nil
}
