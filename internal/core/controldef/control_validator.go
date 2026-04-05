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
func (ctl *ControlDefinition) Validate() []diag.Diagnostic {
	if ctl == nil {
		return nil
	}

	rules := []func() []diag.Diagnostic{
		ctl.validateIdentity,
		ctl.validateDocumentation,
		ctl.validateIDFormat,
		ctl.validateSeverity,
		ctl.validateType,
		ctl.validatePredicate,
		ctl.validateOperators,
		ctl.validateParameters,
		ctl.validateDuration,
	}

	var issues []diag.Diagnostic
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
func (ctl *ControlDefinition) newIssue(code diag.Code, extra map[string]string) *diag.Builder {
	return diag.New(code).WithMap(ctl.issueContext(extra))
}

// --- Validation rules (methods for encapsulation) ---

func (ctl *ControlDefinition) validateIdentity() []diag.Diagnostic {
	if ctl.ID != "" {
		return nil
	}
	return []diag.Diagnostic{
		ctl.newIssue(diag.CodeControlMissingID, nil).
			Error().
			Action("Add a unique 'id' (e.g., CTL.S3.PUBLIC.001) to the control definition").
			Build(),
	}
}

func (ctl *ControlDefinition) validateDocumentation() []diag.Diagnostic {
	var issues []diag.Diagnostic
	if strings.TrimSpace(ctl.Name) == "" {
		issues = append(issues, ctl.newIssue(diag.CodeControlMissingName, nil).
			Error().
			Action("Assign a descriptive 'name' to the control for reporting").
			Build())
	}
	if strings.TrimSpace(ctl.Description) == "" {
		issues = append(issues, ctl.newIssue(diag.CodeControlMissingDesc, nil).
			Error().
			Action("Provide a 'description' explaining the security impact of this control").
			Build())
	}
	return issues
}

func (ctl *ControlDefinition) validateIDFormat() []diag.Diagnostic {
	if ctl.ID == "" {
		return nil
	}
	if err := kernel.ValidateControlIDFormat(ctl.ID.String()); err != nil {
		return []diag.Diagnostic{
			ctl.newIssue(diag.CodeControlBadIDFormat, nil).
				Warning().
				Action("Align ID with standard format: CTL.<PROVIDER>.<CATEGORY>.<SEQ>").
				WithSensitive("error", err.Error()).
				Build(),
		}
	}
	return nil
}

func (ctl *ControlDefinition) validateSeverity() []diag.Diagnostic {
	if ctl.Severity == SeverityNone || ctl.Severity.IsValid() {
		return nil
	}
	return []diag.Diagnostic{
		ctl.newIssue(diag.CodeControlBadSeverity, map[string]string{"severity": ctl.Severity.String()}).
			Warning().
			Action("Use a valid severity: info, low, medium, high, or critical").
			Build(),
	}
}

func (ctl *ControlDefinition) validateType() []diag.Diagnostic {
	if ctl.Type == TypeUnknown || ctl.Type.IsValid() {
		return nil
	}
	return []diag.Diagnostic{
		ctl.newIssue(diag.CodeControlBadType, map[string]string{"type": ctl.Type.String()}).
			Warning().
			Action("Specify a supported control type (e.g., unsafe_state, unsafe_duration)").
			Build(),
	}
}

func (ctl *ControlDefinition) validatePredicate() []diag.Diagnostic {
	if len(ctl.UnsafePredicate.Any) > 0 || len(ctl.UnsafePredicate.All) > 0 {
		return nil
	}
	return []diag.Diagnostic{
		ctl.newIssue(diag.CodeControlEmptyPredicate, nil).
			Warning().
			Action("Define at least one rule under 'any' or 'all' in the unsafe_predicate").
			Build(),
	}
}

func (ctl *ControlDefinition) validateOperators() []diag.Diagnostic {
	var issues []diag.Diagnostic
	ctl.UnsafePredicate.Walk(func(rule PredicateRule) {
		if rule.Field.IsZero() {
			return
		}
		if !predicate.IsSupported(rule.Op) {
			issues = append(issues, ctl.newIssue(diag.CodeControlUnsupportedOperator, map[string]string{
				"field":    rule.Field.String(),
				"operator": string(rule.Op),
			}).
				Warning().
				Action(fmt.Sprintf("Replace unsupported operator %q with a valid one (eq, ne, in, etc.)", rule.Op)).
				Build())
		}
	})
	return issues
}

func (ctl *ControlDefinition) validateParameters() []diag.Diagnostic {
	missing := ctl.UnsafePredicate.MissingParamReferences(ctl.Params)
	if len(missing) == 0 {
		return nil
	}
	issues := make([]diag.Diagnostic, 0, len(missing))
	for _, p := range missing {
		issues = append(issues, ctl.newIssue(diag.CodeControlUndefinedParam, map[string]string{"param": p}).
			Error().
			Action(fmt.Sprintf("Define parameter %q in the control's 'params' section", p)).
			Build())
	}
	return issues
}

func (ctl *ControlDefinition) validateDuration() []diag.Diagnostic {
	const durationKey = "max_unsafe_duration"

	if !ctl.Params.HasKey(durationKey) {
		return nil
	}
	if ctl.Prepared.Ready && ctl.Prepared.HasMaxUnsafeDuration {
		return nil
	}

	raw := ctl.Params.paramString(durationKey)
	if raw == "" {
		return []diag.Diagnostic{
			ctl.newIssue(diag.CodeControlBadDurationParam, map[string]string{"param": durationKey}).
				Error().
				Action("Provide a valid duration (e.g., '30d') for max_unsafe_duration").
				Build(),
		}
	}

	if _, err := kernel.ParseDuration(raw); err != nil {
		return []diag.Diagnostic{
			ctl.newIssue(diag.CodeControlBadDurationParam, map[string]string{"param": durationKey, "value": raw}).
				Error().
				Action("Use valid duration units: 'h' for hours or 'd' for days").
				WithSensitive("error", err.Error()).
				Build(),
		}
	}
	return nil
}
