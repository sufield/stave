package diagnose

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	builtinctl "github.com/sufield/stave/internal/adapters/controls/builtin"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/app/narrative"
	"github.com/sufield/stave/internal/builtin/capabilities"
	"github.com/sufield/stave/internal/controldata"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type explainNarrativeOpts struct {
	FindingID   string
	ControlID   string
	AssetID     string
	OutputFile  string
	ControlsDir string
	ChainsDir   string
	Format      string
	Depth       string
	Out         string
}

// NewExplainNarrativeCmd constructs the diagnose explain subcommand.
func NewExplainNarrativeCmd() *cobra.Command {
	opts := &explainNarrativeOpts{
		ControlsDir: "controls",
		ChainsDir:   "chains",
		Format:      "narrative",
		Depth:       "standard",
	}

	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Generate guided remediation playbook for a finding",
		Long: `Assemble a remediation narrative from structured finding data,
control metadata, and chain context. Explains the security impact,
dependency order for safe remediation, and compound risk context.

No network calls — fully offline, air-gap compatible.

Exit Codes:
  0   Playbook generated
  2   Invalid input
  4   Internal error`,
		Example: `  stave diagnose explain --finding-id sha256:a3f8c2 --output out.v0.1.json
  stave diagnose explain --asset arn:aws:s3:::phi-records --output out.v0.1.json
  stave diagnose explain --control CTL.S3.PUBLIC.001 --output out.v0.1.json --format markdown`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runExplainNarrative(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.FindingID, "finding-id", "", "explain a specific finding by ID")
	cmd.Flags().StringVar(&opts.ControlID, "control", "", "explain all findings for a control")
	cmd.Flags().StringVar(&opts.AssetID, "asset", "", "explain all findings for an asset")
	cmd.Flags().StringVar(&opts.OutputFile, "output", "", "path to out.v0.1.json (required)")
	cmd.Flags().StringVar(&opts.ControlsDir, "controls", opts.ControlsDir, "controls directory")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", opts.ChainsDir, "chains directory")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", opts.Format, "output format: narrative | json | markdown")
	cmd.Flags().StringVar(&opts.Depth, "depth", opts.Depth, "detail level: brief | standard | detailed")
	cmd.Flags().StringVar(&opts.Out, "out", "", "write output to file")

	_ = cmd.MarkFlagRequired("output")

	return cmd
}

func runExplainNarrative(stdout io.Writer, opts *explainNarrativeOpts) error {
	if opts.FindingID == "" && opts.ControlID == "" && opts.AssetID == "" {
		return errors.New("one of --finding-id, --control, or --asset is required")
	}

	// Load assessment.
	data, err := fsutil.ReadFileLimited(opts.OutputFile)
	if err != nil {
		return fmt.Errorf("read assessment: %w", err)
	}
	var assessment report.Assessment
	if jsonErr := json.Unmarshal(data, &assessment); jsonErr != nil {
		return fmt.Errorf("parse assessment: %w", jsonErr)
	}

	// Load controls for metadata.
	store := builtinctl.NewControlStore(controldata.FS, ".")
	controls, ctlErr := store.All()
	if ctlErr != nil {
		slog.Warn("control metadata unavailable for narrative", "error", ctlErr)
	}
	controlMap := make(map[kernel.ControlID]*policy.ControlDefinition, len(controls))
	for i := range controls {
		controlMap[controls[i].ID] = &controls[i]
	}

	// Load chains.
	chains, chainsErr := ctlyaml.LoadChains(opts.ChainsDir, capabilities.Builtin())
	if chainsErr != nil {
		return fmt.Errorf("loading chains: %w", chainsErr)
	}

	// Filter findings.
	var selected []int
	for i := range assessment.Findings {
		f := &assessment.Findings[i]
		switch {
		case opts.FindingID != "" && f.FindingID == opts.FindingID:
			selected = append(selected, i)
		case opts.ControlID != "" && string(f.ControlID) == opts.ControlID:
			selected = append(selected, i)
		case opts.AssetID != "" && string(f.AssetID) == opts.AssetID:
			selected = append(selected, i)
		}
	}

	if len(selected) == 0 {
		return errors.New("no matching findings found")
	}

	// Build playbooks.
	playbooks := make([]narrative.Playbook, len(selected))
	for i, idx := range selected {
		f := assessment.Findings[idx]
		ctl := controlMap[f.ControlID]
		playbooks[i] = narrative.BuildPlaybook(&narrative.Input{
			Finding:     f,
			Control:     ctl,
			ChainDefs:   chains,
			AllFindings: assessment.Findings,
		})
	}

	// Write output.
	out := stdout
	if opts.Out != "" {
		f, createErr := os.Create(opts.Out)
		if createErr != nil {
			return fmt.Errorf("create output: %w", createErr)
		}
		defer f.Close()
		out = f
	}

	switch opts.Format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if len(playbooks) == 1 {
			return enc.Encode(playbooks[0])
		}
		return enc.Encode(playbooks)
	case "markdown":
		writeMarkdownPlaybooks(out, playbooks, opts.Depth)
	default:
		writeNarrativePlaybooks(out, playbooks, opts.Depth)
	}
	return nil
}

func writeNarrativePlaybooks(w io.Writer, playbooks []narrative.Playbook, depth string) {
	if len(playbooks) > 1 {
		fmt.Fprintf(w, "ASSET REMEDIATION PLAYBOOK\nFailing controls: %d\n\n", len(playbooks))
	}

	for pi := range playbooks {
		pb := &playbooks[pi]

		// Section 1: Finding summary (always shown).
		fmt.Fprintf(w, "FINDING: %s — %s\n", pb.ControlID, pb.ControlName)
		fmt.Fprintf(w, "Asset:   %s\n", pb.AssetID)
		fmt.Fprintf(w, "Verdict: FAIL (%s)\n", pb.Severity)
		fmt.Fprintf(w, "ID:      %s\n", pb.FindingID)

		if depth == "brief" {
			// Brief: skip to steps.
			writeNarrativeSteps(w, pb.Narrative.Steps)
			fmt.Fprintln(w)
			continue
		}

		// Section 2: Why this matters.
		if pb.Narrative.WhyThisMatters != "" {
			fmt.Fprintln(w, "\nWHY THIS MATTERS")
			fmt.Fprintln(w, strings.Repeat("\u2500", 64))
			fmt.Fprintln(w, pb.Narrative.WhyThisMatters)
		}

		// Section 3: Current state.
		if len(pb.Narrative.CurrentState) > 0 {
			fmt.Fprintln(w, "\nCURRENT STATE")
			fmt.Fprintln(w, strings.Repeat("\u2500", 64))
			for _, s := range pb.Narrative.CurrentState {
				marker := ""
				if s.RequiredValue != "" {
					marker = "  \u2190 must be " + s.RequiredValue
				}
				fmt.Fprintf(w, "  %-40s %s%s\n", s.PropertyPath+":", s.CurrentValue, marker)
			}
		}

		// Section 4: Steps.
		writeNarrativeSteps(w, pb.Narrative.Steps)

		// Section 5: Chain context.
		if pb.Narrative.ChainContext != nil {
			cc := pb.Narrative.ChainContext
			fmt.Fprintln(w, "\nCOMPOUND CHAIN CONTEXT")
			fmt.Fprintln(w, strings.Repeat("\u2500", 64))
			fmt.Fprintf(w, "Chain: %s (ACTIVE)\n", cc.ChainID)
			for _, m := range cc.MemberControls {
				icon := "\u2717"
				label := m.Status
				if m.Status == "passing" {
					icon = "\u2713"
				}
				fmt.Fprintf(w, "  %s %s  %s\n", icon, m.ControlID, label)
			}
			if cc.ChainNarrative != "" {
				fmt.Fprintf(w, "\n%s\n", cc.ChainNarrative)
			}
			if len(cc.DeactivationOrder) > 0 {
				fmt.Fprintln(w, "\nRecommended deactivation order:")
				for i, id := range cc.DeactivationOrder {
					fmt.Fprintf(w, "  %d. %s\n", i+1, id)
				}
			}
		}

		fmt.Fprintln(w)
	}
}

func writeNarrativeSteps(w io.Writer, steps []narrative.Step) {
	if len(steps) == 0 {
		return
	}
	fmt.Fprintln(w, "\nREMEDIATION STEPS")
	fmt.Fprintln(w, strings.Repeat("\u2500", 64))
	for _, s := range steps {
		safeLabel := ""
		if s.SafeDefault {
			safeLabel = "  [SAFE DEFAULT]"
		}
		fmt.Fprintf(w, "Step %d of %d — %s%s\n", s.StepNumber, len(steps), s.Title, safeLabel)
		if s.Caution != "" {
			fmt.Fprintf(w, "  \u26a0 CAUTION: %s\n", s.Caution)
		}
		if s.Action != "" {
			fmt.Fprintf(w, "  %s\n", s.Action)
		}
		if s.Confidence != "" {
			fmt.Fprintf(w, "  Confidence: %s\n", strings.ToUpper(s.Confidence))
		}
	}
}

func writeMarkdownPlaybooks(w io.Writer, playbooks []narrative.Playbook, depth string) {
	for pi := range playbooks {
		pb := &playbooks[pi]

		fmt.Fprintf(w, "# %s — %s\n\n", pb.ControlID, pb.ControlName)
		fmt.Fprintf(w, "**Asset:** %s  \n", pb.AssetID)
		fmt.Fprintf(w, "**Severity:** %s  \n", pb.Severity)
		fmt.Fprintf(w, "**Finding ID:** %s  \n\n", pb.FindingID)

		if depth != "brief" && pb.Narrative.WhyThisMatters != "" {
			fmt.Fprintf(w, "## Why This Matters\n\n%s\n\n", pb.Narrative.WhyThisMatters)
		}

		if depth != "brief" && len(pb.Narrative.CurrentState) > 0 {
			fmt.Fprintln(w, "## Current State")
			fmt.Fprintln(w, "| Property | Current | Required |")
			fmt.Fprintln(w, "|---|---|---|")
			for _, s := range pb.Narrative.CurrentState {
				fmt.Fprintf(w, "| %s | %s | %s |\n", s.PropertyPath, s.CurrentValue, s.RequiredValue)
			}
			fmt.Fprintln(w)
		}

		fmt.Fprintln(w, "## Remediation Steps")
		for _, s := range pb.Narrative.Steps {
			safe := ""
			if s.SafeDefault {
				safe = " [SAFE DEFAULT]"
			}
			fmt.Fprintf(w, "### Step %d: %s%s\n\n", s.StepNumber, s.Title, safe)
			if s.Caution != "" {
				fmt.Fprintf(w, "> **CAUTION:** %s\n\n", s.Caution)
			}
			if s.Action != "" {
				fmt.Fprintf(w, "%s\n\n", s.Action)
			}
		}

		if depth != "brief" && pb.Narrative.ChainContext != nil {
			cc := pb.Narrative.ChainContext
			fmt.Fprintf(w, "## Chain Context: %s\n\n", cc.ChainID)
			for _, m := range cc.MemberControls {
				icon := "x"
				if m.Status == "passing" {
					icon = "v"
				}
				fmt.Fprintf(w, "- [%s] %s (%s)\n", icon, m.ControlID, m.Status)
			}
			fmt.Fprintln(w)
		}

		fmt.Fprintln(w, "---")
	}
}
