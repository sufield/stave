package controldef

import (
	"fmt"
	"maps"
	"strings"

	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// Validate performs a comprehensive logical and structural audit of a
// control's configuration. Returns nil if the control is valid.
func (ctl *ControlDefinition) Validate() []diag.Finding {
	if ctl == nil {
		return nil
	}

	rules := []func() []diag.Finding{
		ctl.validateIdentity,
		ctl.validateDocumentation,
		ctl.validateIDFormat,
		ctl.validateSeverity,
		ctl.validateType,
		ctl.validatePredicate,
		ctl.validatePredicateRules,
		ctl.validateOperators,
		ctl.validateParameters,
		ctl.validateDuration,
	}

	var issues []diag.Finding
	for _, rule := range rules {
		issues = append(issues, rule()...)
	}
	return issues
}

// issueContext generates the standard diagnostic evidence map for this control.
func (ctl *ControlDefinition) issueContext(extra map[string]string) map[string]string {
	ctx := make(map[string]string, 2+len(extra))
	if ctl.ID != "" {
		ctx["control_id"] = ctl.ID.String()
	}
	if desc := strings.TrimSpace(ctl.Description); desc != "" {
		ctx["description"] = desc
	}
	if len(extra) > 0 {
		maps.Copy(ctx, extra)
	}
	return ctx
}

// newIssue starts a diagnostic builder pre-populated with control context.
func (ctl *ControlDefinition) newIssue(code diag.RuleID, extra map[string]string) *diag.Builder {
	return diag.NewFinding(code).Attributes(ctl.issueContext(extra))
}

// --- Validation rules (methods for encapsulation) ---

func (ctl *ControlDefinition) validateIdentity() []diag.Finding {
	if ctl.ID != "" {
		return nil
	}
	return []diag.Finding{
		ctl.newIssue(diag.RuleControlMissingID, nil).
			Error().
			Remediation("Add a unique 'id' (e.g., CTL.S3.PUBLIC.001) to the control definition").
			Build(),
	}
}

func (ctl *ControlDefinition) validateDocumentation() []diag.Finding {
	var issues []diag.Finding
	if ctl.Name == "" {
		issues = append(issues, ctl.newIssue(diag.RuleControlMissingName, nil).
			Error().
			Remediation("Assign a descriptive 'name' to the control for reporting").
			Build())
	}
	if ctl.Description == "" {
		issues = append(issues, ctl.newIssue(diag.RuleControlMissingDesc, nil).
			Error().
			Remediation("Provide a 'description' explaining the security impact of this control").
			Build())
	}
	return issues
}

func (ctl *ControlDefinition) validateIDFormat() []diag.Finding {
	if ctl.ID == "" {
		return nil
	}
	if err := kernel.ValidateControlIDFormat(ctl.ID.String()); err != nil {
		return []diag.Finding{
			ctl.newIssue(diag.RuleControlBadIDFormat, nil).
				Warning().
				Remediation("Align ID with standard format: CTL.<PROVIDER>.<CATEGORY>.<SEQ>").
				SensitiveAttribute("error", err.Error()).
				Build(),
		}
	}
	return nil
}

func (ctl *ControlDefinition) validateSeverity() []diag.Finding {
	if ctl.Severity == SeverityNone || ctl.Severity.IsValid() {
		return nil
	}
	return []diag.Finding{
		ctl.newIssue(diag.RuleControlBadSeverity, map[string]string{"severity": ctl.Severity.String()}).
			Warning().
			Remediation("Use a valid severity: info, low, medium, high, or critical").
			Build(),
	}
}

func (ctl *ControlDefinition) validateType() []diag.Finding {
	if ctl.Type == TypeUnknown || ctl.Type.IsValid() {
		return nil
	}
	return []diag.Finding{
		ctl.newIssue(diag.RuleControlBadType, map[string]string{"type": ctl.Type.String()}).
			Warning().
			Remediation("Specify a supported control type (e.g., unsafe_state, unsafe_duration)").
			Build(),
	}
}

func (ctl *ControlDefinition) validatePredicate() []diag.Finding {
	if len(ctl.UnsafePredicate.Any) > 0 || len(ctl.UnsafePredicate.All) > 0 {
		return nil
	}
	return []diag.Finding{
		ctl.newIssue(diag.RuleControlEmptyPredicate, nil).
			Warning().
			Remediation("Define at least one rule under 'any' or 'all' in the unsafe_predicate").
			Build(),
	}
}

func (ctl *ControlDefinition) validateOperators() []diag.Finding {
	var issues []diag.Finding
	ctl.UnsafePredicate.Walk(func(rule PredicateRule) {
		if rule.Field.IsZero() {
			return
		}
		if !predicate.IsSupported(rule.Op) {
			issues = append(issues, ctl.newIssue(diag.RuleControlUnsupportedOperator, map[string]string{
				"field":    rule.Field.String(),
				"operator": string(rule.Op),
			}).
				Warning().
				Remediation(fmt.Sprintf("Replace unsupported operator %q with a valid one (eq, ne, in, etc.)", rule.Op)).
				Build())
		}
	})
	return issues
}

func (ctl *ControlDefinition) validateParameters() []diag.Finding {
	missing := ctl.UnsafePredicate.MissingParamReferences(ctl.Params)
	if len(missing) == 0 {
		return nil
	}
	issues := make([]diag.Finding, 0, len(missing))
	for _, p := range missing {
		issues = append(issues, ctl.newIssue(diag.RuleControlUndefinedParam, map[string]string{"param": p}).
			Error().
			Remediation(fmt.Sprintf("Define parameter %q in the control's 'params' section", p)).
			Build())
	}
	return issues
}

func (ctl *ControlDefinition) validateDuration() []diag.Finding {
	const durationKey = "max_unsafe_duration"

	if !ctl.Params.HasKey(durationKey) {
		return nil
	}
	if ctl.prepared.Ready && ctl.prepared.HasMaxUnsafeDuration {
		return nil
	}

	raw := ctl.Params.paramString(durationKey)
	if raw == "" {
		return []diag.Finding{
			ctl.newIssue(diag.RuleControlBadDurationParam, map[string]string{"param": durationKey}).
				Error().
				Remediation("Provide a valid duration (e.g., '30d') for max_unsafe_duration").
				Build(),
		}
	}

	if _, err := kernel.ParseDuration(raw); err != nil {
		return []diag.Finding{
			ctl.newIssue(diag.RuleControlBadDurationParam, map[string]string{"param": durationKey, "value": raw}).
				Error().
				Remediation("Use valid duration units: 'h' for hours or 'd' for days").
				SensitiveAttribute("error", err.Error()).
				Build(),
		}
	}
	return nil
}

// validatePredicateRules checks for leaf rules with empty field paths —
// these silently produce no-op logic that never matches any resource.
func (ctl *ControlDefinition) validatePredicateRules() []diag.Finding {
	var issues []diag.Finding
	ctl.UnsafePredicate.Walk(func(rule PredicateRule) {
		isLeaf := len(rule.Any) == 0 && len(rule.All) == 0
		if isLeaf && rule.Field.IsZero() && rule.Op == "" {
			issues = append(issues, ctl.newIssue(diag.RuleControlEmptyPredicate, nil).
				Warning().
				Remediation("Remove empty predicate rule or add a field and operator").
				Build())
		}
	})
	return issues
}
