package diagnose

import (
	"context"
	"fmt"
	"io"
	"sort"
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

type explainFlagsType struct {
	controlsDir string
	format      string
}

type explainRule struct {
	Path    string             `json:"path"`
	Op      predicate.Operator `json:"op"`
	Value   any                `json:"value,omitempty"`
	From    string             `json:"from,omitempty"`
	Comment string             `json:"comment,omitempty"`
}

type explainOutput struct {
	ControlID          string        `json:"control_id"`
	Name               string        `json:"name"`
	Description        string        `json:"description"`
	Type               string        `json:"type"`
	MatchedFields      []string      `json:"matched_fields"`
	Rules              []explainRule `json:"rules"`
	MinimalObservation any           `json:"minimal_observation"`
}

// NewExplainCmd constructs the explain command with closure-scoped flags.
func NewExplainCmd() *cobra.Command {
	var flags explainFlagsType

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
			return RunExplain(cmd, args, flags.controlsDir, flags.format)
		},
	}

	cmd.Flags().StringVar(&flags.controlsDir, "controls", "controls/s3", "Path to control definitions directory")
	cmd.Flags().StringVarP(&flags.format, "format", "f", "text", "Output format: text or json")

	return cmd
}

// RunExplain implements the explain logic shared between the top-level
// explain command and the controls explain sub-command.
func RunExplain(cmd *cobra.Command, args []string, controlsDir, format string) error {
	id := strings.TrimSpace(args[0])
	if id == "" {
		return &ui.UserError{Err: fmt.Errorf("control id cannot be empty")}
	}
	controlPath := strings.TrimSpace(controlsDir)
	control, err := loadExplainControl(compose.CommandContext(cmd), id, controlPath)
	if err != nil {
		return err
	}
	out := buildExplainOutput(control)
	resolvedFormat, err := compose.ResolveFormatValue(cmd, format)
	if err != nil {
		return err
	}
	return writeExplainOutput(cmd.OutOrStdout(), resolvedFormat, out)
}

func loadExplainControl(ctx context.Context, id, controlsDir string) (policy.ControlDefinition, error) {
	ctl, err := compose.LoadControlByID(ctx, controlsDir, id)
	if err != nil {
		return policy.ControlDefinition{}, ui.WithNextCommand(err,
			fmt.Sprintf("stave validate --controls %s", controlsDir))
	}
	return *ctl, nil
}

func buildExplainOutput(ctl policy.ControlDefinition) explainOutput {
	fields, rules := explainPredicate(ctl.UnsafePredicate, ctl.Params)
	sort.Strings(fields)
	return explainOutput{
		ControlID:          ctl.ID.String(),
		Name:               ctl.Name,
		Description:        ctl.Description,
		Type:               ctl.Type.String(),
		MatchedFields:      fields,
		Rules:              rules,
		MinimalObservation: buildMinimalObservation(fields, rules),
	}
}

func writeExplainOutput(w io.Writer, format ui.OutputFormat, out explainOutput) error {
	if format.IsJSON() {
		return jsonutil.WriteIndented(w, out)
	}
	return writeExplainText(w, out)
}

func explainPredicate(pred policy.UnsafePredicate, params policy.ControlParams) ([]string, []explainRule) {
	rules, fieldSet := walkPredicateRules("any", pred.Any, params)
	allRules, allFields := walkPredicateRules("all", pred.All, params)
	rules = append(rules, allRules...)
	for f := range allFields {
		fieldSet[f] = true
	}

	fields := make([]string, 0, len(fieldSet))
	for f := range fieldSet {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	return fields, rules
}

func walkPredicateRules(from string, prs []policy.PredicateRule, params policy.ControlParams) ([]explainRule, map[string]bool) {
	var rules []explainRule
	fieldSet := map[string]bool{}
	for i := range prs {
		r := prs[i]
		loc := fmt.Sprintf("%s[%d]", from, i)
		if len(r.Any) > 0 {
			rules, fieldSet = mergeNestedRules(rules, fieldSet, loc+".any", r.Any, params)
		}
		if len(r.All) > 0 {
			rules, fieldSet = mergeNestedRules(rules, fieldSet, loc+".all", r.All, params)
		}
		if r.Field == "" {
			continue
		}
		value, comment := resolveRuleValue(r, params)
		rules = append(rules, explainRule{
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

func mergeNestedRules(
	rules []explainRule, fieldSet map[string]bool,
	loc string, nested []policy.PredicateRule, params policy.ControlParams,
) ([]explainRule, map[string]bool) {
	sub, nf := walkPredicateRules(loc, nested, params)
	rules = append(rules, sub...)
	for f := range nf {
		fieldSet[f] = true
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

func buildMinimalObservation(fields []string, rules []explainRule) map[string]any {
	props := map[string]any{}
	valueByPath := map[string]any{}
	for _, r := range rules {
		if r.Path == "" {
			continue
		}
		valueByPath[r.Path] = sampleValueForRule(r)
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

func sampleValueForRule(r explainRule) any {
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

func writeExplainText(w io.Writer, out explainOutput) error {
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

func writeExplainHeader(w io.Writer, out explainOutput) error {
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

func writeExplainRules(w io.Writer, rules []explainRule) error {
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
