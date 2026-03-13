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
	"github.com/sufield/stave/internal/domain/kernel"
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

func (e *Explainer) walkPredicate(pred policy.UnsafePredicate, params policy.ControlParams) ([]string, []ExplainRule) {
	rules, fieldSet := walkRules("any", pred.Any, params)
	allRules, allFields := walkRules("all", pred.All, params)
	rules = append(rules, allRules...)
	for f := range allFields {
		fieldSet[f] = true
	}

	fields := make([]string, 0, len(fieldSet))
	for f := range fieldSet {
		fields = append(fields, f)
	}
	slices.Sort(fields)
	return fields, rules
}

func walkRules(from string, prs []policy.PredicateRule, params policy.ControlParams) ([]ExplainRule, map[string]bool) {
	var rules []ExplainRule
	fieldSet := map[string]bool{}
	for i := range prs {
		r := prs[i]
		loc := fmt.Sprintf("%s[%d]", from, i)
		if len(r.Any) > 0 {
			sub, nf := walkRules(loc+".any", r.Any, params)
			rules = append(rules, sub...)
			for f := range nf {
				fieldSet[f] = true
			}
		}
		if len(r.All) > 0 {
			sub, nf := walkRules(loc+".all", r.All, params)
			rules = append(rules, sub...)
			for f := range nf {
				fieldSet[f] = true
			}
		}
		if r.Field == "" {
			continue
		}
		value, comment := resolveRuleValue(r, params)
		rules = append(rules, ExplainRule{
			Path:    r.Field,
			Op:      r.Op,
			Value:   value,
			From:    loc,
			Comment: comment,
		})
		fieldSet[r.Field] = true
	}
	return rules, fieldSet
}

func resolveRuleValue(r policy.PredicateRule, params policy.ControlParams) (value any, comment string) {
	value = r.Value
	if r.ValueFromParam != "" && params != nil {
		value = params[r.ValueFromParam]
	}
	if r.ValueFromParam != "" {
		comment = "value resolved from params." + r.ValueFromParam
	}
	return value, comment
}

func (e *Explainer) buildMinimalObservation(fields []string, rules []ExplainRule) map[string]any {
	props := map[string]any{}
	valueByPath := map[string]any{}
	for _, r := range rules {
		if r.Path == "" {
			continue
		}
		valueByPath[r.Path] = sampleValue(r)
	}

	for _, fullPath := range fields {
		trimmed := strings.TrimPrefix(fullPath, "properties.")
		if trimmed == "" || trimmed == fullPath && strings.HasPrefix(fullPath, "properties.") {
			continue
		}
		setNested(props, trimmed, valueByPath[fullPath])
	}

	return map[string]any{
		"schema_version": string(kernel.SchemaObservation),
		"generated_by": map[string]any{
			"source_type": "aws-s3-snapshot",
			"tool":        "stave-explain",
		},
		"captured_at": "2026-01-18T00:00:00Z",
		"assets": []map[string]any{
			{
				"id":         "example-asset",
				"type":       "aws_s3_bucket",
				"vendor":     "aws",
				"properties": props,
			},
		},
	}
}

func sampleValue(r ExplainRule) any {
	if r.Op == predicate.OpMissing {
		return nil
	}
	if r.Value != nil {
		return r.Value
	}
	switch r.Op {
	case predicate.OpEq, predicate.OpNe:
		return false
	case predicate.OpContains, predicate.OpIn:
		return "example"
	case predicate.OpPresent:
		return "example"
	default:
		return "example"
	}
}

func setNested(root map[string]any, dotted string, val any) {
	if dotted == "" {
		return
	}
	parts := strings.Split(dotted, ".")
	curr := root
	for i, p := range parts {
		if i == len(parts)-1 {
			if val != nil {
				curr[p] = val
			}
			return
		}
		next, ok := curr[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			curr[p] = next
		}
		curr = next
	}
}

// --- Text rendering ---

func writeExplainText(w io.Writer, out ExplainResult) error {
	if err := writeExplainHeader(w, out); err != nil {
		return err
	}
	if err := writeExplainMatchedFields(w, out.MatchedFields); err != nil {
		return err
	}
	if err := writeExplainRules(w, out.Rules); err != nil {
		return err
	}
	if err := writeExplainMinimalObservation(w, out.MinimalObservation); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, "Next: save this JSON under ./observations/<timestamp>.json, then run `stave validate --controls ./controls --observations ./observations`")
	return err
}

func writeExplainHeader(w io.Writer, out ExplainResult) error {
	lines := []string{
		fmt.Sprintf("Control: %s", out.ControlID),
		fmt.Sprintf("Name: %s", out.Name),
		fmt.Sprintf("Description: %s", out.Description),
		fmt.Sprintf("Type: %s", out.Type),
		"",
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func writeExplainMatchedFields(w io.Writer, fields []string) error {
	if _, err := fmt.Fprintln(w, "Matched fields:"); err != nil {
		return err
	}
	for _, field := range fields {
		if _, err := fmt.Fprintf(w, "  - %s\n", field); err != nil {
			return err
		}
	}
	return nil
}

func writeExplainRules(w io.Writer, rules []ExplainRule) error {
	if _, err := fmt.Fprintln(w, "\nRules:"); err != nil {
		return err
	}
	for _, rule := range rules {
		if _, err := fmt.Fprintf(w, "  - %s %s %v (%s)\n", rule.Path, rule.Op, rule.Value, rule.From); err != nil {
			return err
		}
	}
	return nil
}

func writeExplainMinimalObservation(w io.Writer, observation any) error {
	if _, err := fmt.Fprintln(w, "\nMinimal observation snippet:"); err != nil {
		return err
	}
	return jsonutil.WriteIndented(w, observation)
}

// --- CLI bridge ---

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
