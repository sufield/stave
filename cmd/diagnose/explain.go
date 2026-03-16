package diagnose

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/predicate"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// ExplainRequest holds the inputs for the explain workflow.
type ExplainRequest struct {
	ControlID   string
	ControlsDir string
	Format      ui.OutputFormat
	Stdout      io.Writer
}

// ExplainResult holds the structured output of an explain analysis.
type ExplainResult struct {
	ControlID          string        `json:"control_id"`
	Name               string        `json:"name"`
	Description        string        `json:"description"`
	Type               string        `json:"type"`
	MatchedFields      []string      `json:"matched_fields"`
	Rules              []ExplainRule `json:"rules"`
	MinimalObservation any           `json:"minimal_observation"`
}

// ExplainRule describes a single predicate rule.
type ExplainRule struct {
	Path    string             `json:"path"`
	Op      predicate.Operator `json:"op"`
	Value   any                `json:"value,omitempty"`
	From    string             `json:"from,omitempty"`
	Comment string             `json:"comment,omitempty"`
}

// Explainer analyzes a control and explains its predicate structure.
type Explainer struct {
	Provider *compose.Provider
}

// NewExplainer creates an Explainer with the given provider.
func NewExplainer(p *compose.Provider) *Explainer {
	return &Explainer{Provider: p}
}

// Run executes the explain workflow.
func (e *Explainer) Run(ctx context.Context, req ExplainRequest) error {
	id := strings.TrimSpace(req.ControlID)
	if id == "" {
		return &ui.UserError{Err: fmt.Errorf("control id cannot be empty")}
	}
	controlsDir := strings.TrimSpace(req.ControlsDir)
	ctl, err := e.loadControl(ctx, id, controlsDir)
	if err != nil {
		return err
	}
	result := e.analyze(ctl)
	return e.write(req.Stdout, req.Format, result)
}

func (e *Explainer) loadControl(ctx context.Context, id, controlsDir string) (policy.ControlDefinition, error) {
	ctl, err := compose.LoadControlByID(ctx, controlsDir, id)
	if err != nil {
		return policy.ControlDefinition{}, ui.WithNextCommand(err,
			fmt.Sprintf("stave validate --controls %s", controlsDir))
	}
	return ctl, nil
}

func (e *Explainer) analyze(ctl policy.ControlDefinition) ExplainResult {
	fields, rules := e.walkPredicate(ctl.UnsafePredicate, ctl.Params)
	slices.Sort(fields)
	return ExplainResult{
		ControlID:          ctl.ID.String(),
		Name:               ctl.Name,
		Description:        ctl.Description,
		Type:               ctl.Type.String(),
		MatchedFields:      fields,
		Rules:              rules,
		MinimalObservation: e.buildMinimalObservation(fields, rules),
	}
}

func (e *Explainer) write(w io.Writer, format ui.OutputFormat, result ExplainResult) error {
	if format.IsJSON() {
		return jsonutil.WriteIndented(w, result)
	}
	return writeExplainText(w, result)
}

// NewExplainCmd constructs the explain command.
func NewExplainCmd() *cobra.Command {
	var (
		controlsDir string
		format      string
	)

	cmd := &cobra.Command{
		Use:   "explain <control-id>",
		Short: "Explain how a control evaluates and which fields it needs",
		Long: `Explain loads a single control and prints:
  - matched field paths used by predicates
  - operator/value expectations
  - a minimal obs.v0.1 snippet you can start from

Examples:
  stave explain CTL.S3.PUBLIC.001
  stave explain CTL.S3.PUBLIC.001 --controls ./controls
  stave explain CTL.S3.PUBLIC.001 --format json` + metadata.OfflineHelpSuffix,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmtValue, fmtErr := compose.ResolveFormatValue(cmd, format)
			if fmtErr != nil {
				return fmtErr
			}
			explainer := NewExplainer(compose.ActiveProvider())
			return explainer.Run(cmd.Context(), ExplainRequest{
				ControlID:   args[0],
				ControlsDir: controlsDir,
				Format:      fmtValue,
				Stdout:      cmd.OutOrStdout(),
			})
		},
	}

	cmd.Flags().StringVar(&controlsDir, "controls", "controls/s3", "Path to control definitions directory")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")

	return cmd
}
