package newcmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

type options struct {
	Output string
}

// NewCmd constructs the template new command.
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "new [template-name]",
		Short: "Scaffold a new custom template",
		Long: `Create a blank template scaffold for authoring. Generates a
template.yaml with placeholder values and an empty fixture directory.

Inputs:
  template-name       Name for the new template (positional)
  --output DIR        Output directory (default: ./stave-templates/<name>)

Outputs:
  template.yaml and fixtures/ directory

Exit Codes:
  0   Scaffold created
  2   Invalid input or directory already exists
  4   Internal error`,
		Example: `  # Scaffold a new template
  stave template new my-org-assessment

  # Scaffold to a custom location
  stave template new my-org-assessment --output ~/.stave/templates/my-org-assessment`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runNew(cmd.OutOrStdout(), args[0], opts)
		},
	}

	cmd.Flags().StringVar(&opts.Output, "output", "", "output directory (default: ./stave-templates/<name>)")

	return cmd
}

func runNew(w io.Writer, name string, opts *options) error {
	outDir := opts.Output
	if outDir == "" {
		outDir = filepath.Join(".", "stave-templates", name)
	}

	if _, err := os.Stat(outDir); err == nil {
		return fmt.Errorf("directory %s already exists", outDir)
	}

	fixtureDir := filepath.Join(outDir, "fixtures")
	if err := os.MkdirAll(fixtureDir, 0o750); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	templateYAML := fmt.Sprintf(`apiVersion: stave/v1
kind: Template
metadata:
  name: %s
  description: ""  # What this template evaluates and why
  job: ""           # The job this template accomplishes in one sentence
  version: "0.1.0"

recommend_when:
  predicate: "true"  # Replace with a CEL predicate over snapshot summary
  priority: 40

parameters: []
  # - name: example_param
  #   description: "What this parameter controls"
  #   type: string
  #   required: true
  #   default: ""

scope:
  services: []  # Which services to include (e.g., iam, s3, cloudtrail)

controls:
  include: []   # Control patterns to include (e.g., "CTL.IAM.*")
  exclude: []   # Control patterns to exclude

chains:
  include: []   # Chain rule sets to evaluate

runbook:
  steps:
    - action: eval
      description: "Evaluate selected controls"
      args:
        snapshot: "{{ .SnapshotPath }}"
        controls: "{{ .ControlSelection }}"
    - action: report
      description: "Export findings"
      args:
        format: jsonl
        output: "{{ .OutputPath }}"

fixture:
  snapshot: "fixtures/snapshot.json"
  expected_findings: "fixtures/expected.jsonl"
  match_keys: ["control_id", "resource_id"]
`, name)

	if err := os.WriteFile(filepath.Join(outDir, "template.yaml"), []byte(templateYAML), 0o600); err != nil {
		return fmt.Errorf("write template.yaml: %w", err)
	}

	emptySnapshot := `{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-01-01T00:00:00Z",
  "generated_by": {"source_type": "manual", "tool": "template-fixture"},
  "assets": []
}
`
	if err := os.WriteFile(filepath.Join(fixtureDir, "snapshot.json"), []byte(emptySnapshot), 0o600); err != nil {
		return fmt.Errorf("write fixture snapshot: %w", err)
	}

	if err := os.WriteFile(filepath.Join(fixtureDir, "expected.jsonl"), []byte(""), 0o600); err != nil {
		return fmt.Errorf("write expected findings: %w", err)
	}

	fmt.Fprintf(w, "Created template scaffold at %s/\n", outDir)
	fmt.Fprintf(w, "  template.yaml          # manifest with placeholder values\n")
	fmt.Fprintf(w, "  fixtures/\n")
	fmt.Fprintf(w, "    snapshot.json         # empty fixture (replace with your test data)\n")
	fmt.Fprintf(w, "    expected.jsonl        # empty expected findings (fill after first run)\n")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Next steps:")
	fmt.Fprintln(w, "  1. Edit template.yaml — set your controls, chains, and recommend_when predicate")
	fmt.Fprintln(w, "  2. Place a test snapshot in fixtures/snapshot.json")
	fmt.Fprintf(w, "  3. Run: stave apply --snapshot fixtures/snapshot.json to generate findings\n")
	fmt.Fprintln(w, "  4. Copy the findings you expect to fixtures/expected.jsonl")
	fmt.Fprintf(w, "  5. Verify: stave template verify %s\n", name)

	return nil
}
