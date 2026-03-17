package policy

import (
	"fmt"
	"maps"
	"strings"

	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/predicate"
)

// ValidateControlDefinition performs a comprehensive check of a control's
// configuration, returning a list of logical errors or configuration warnings.
func ValidateControlDefinition(ctl *ControlDefinition) []diag.Issue {
	if ctl == nil {
		return nil
	}

	// Registry of validation rules to apply
	rules := []func(*ControlDefinition) []diag.Issue{
		validateRequiredMetadata,
		validateIdentity,
		validateSeverity,
		validateLogicType,
		validatePredicateRules,
		validateOperatorSupport,
		validateParameterReferences,
		validateDurationConstraints,
	}

	var issues []diag.Issue
	for _, run := range rules {
		issues = append(issues, run(ctl)...)
	}
	return issues
}

// buildCtx creates the standard diagnostic evidence map for a control.
func buildCtx(ctl *ControlDefinition, extra map[string]string) map[string]string {
	m := make(map[string]string, len(extra)+2)
	if ctl.ID != "" {
		m["control_id"] = ctl.ID.String()
	}
	if d := strings.TrimSpace(ctl.Description); d != "" {
		m["description"] = d
	}
	maps.Copy(m, extra)
	return m
}

func validateRequiredMetadata(ctl *ControlDefinition) []diag.Issue {
	var issues []diag.Issue
	ctx := buildCtx(ctl, nil)

	if ctl.ID == "" {
		issues = append(issues, diag.New(diag.CodeControlMissingID).
			Error().
			Action("Add 'id: CTL.<PROVIDER>.<CATEGORY>.<SEQ>' to the control YAML").
			WithMap(ctx).
			Build())
	}

	if strings.TrimSpace(ctl.Name) == "" {
		issues = append(issues, diag.New(diag.CodeControlMissingName).
			Error().
			Action("Provide a short, descriptive 'name' for the control").
			WithMap(ctx).
			Build())
	}

	if strings.TrimSpace(ctl.Description) == "" {
		issues = append(issues, diag.New(diag.CodeControlMissingDesc).
			Error().
			Action("Provide a 'description' explaining the security impact of this control").
			WithMap(ctx).
			Build())
	}

	return issues
}

func validateIdentity(ctl *ControlDefinition) []diag.Issue {
	if ctl.ID == "" {
		return nil
	}

	if err := kernel.ValidateControlIDFormat(ctl.ID.String()); err != nil {
		return []diag.Issue{
			diag.New(diag.CodeControlBadIDFormat).
				Warning().
				Action("Use format CTL.<PROVIDER>.<CATEGORY>.<SEQ> (e.g., CTL.STORAGE.PUBLIC.001)").
				WithMap(buildCtx(ctl, nil)).
				WithSensitive("error", err.Error()).
				Build(),
		}
	}
	return nil
}

func validateSeverity(ctl *ControlDefinition) []diag.Issue {
	if ctl.Severity == SeverityNone || ctl.Severity.IsValid() {
		return nil
	}

	return []diag.Issue{
		diag.New(diag.CodeControlBadSeverity).
			Warning().
			Action("Assign a valid severity: info, low, medium, high, or critical").
			WithMap(buildCtx(ctl, map[string]string{"severity": ctl.Severity.String()})).
			Build(),
	}
}

func validateLogicType(ctl *ControlDefinition) []diag.Issue {
	if ctl.Type == TypeUnknown || ctl.Type.IsValid() {
		return nil
	}

	return []diag.Issue{
		diag.New(diag.CodeControlBadType).
			Warning().
			Action("Specify a supported control type (e.g., unsafe_state, unsafe_duration)").
			WithMap(buildCtx(ctl, map[string]string{"type": ctl.Type.String()})).
			Build(),
	}
}

func validatePredicateRules(ctl *ControlDefinition) []diag.Issue {
	if len(ctl.UnsafePredicate.Any) == 0 && len(ctl.UnsafePredicate.All) == 0 {
		return []diag.Issue{
			diag.New(diag.CodeControlEmptyPredicate).
				Warning().
				Action("Define logical rules under 'unsafe_predicate: any' or 'all'").
				WithMap(buildCtx(ctl, nil)).
				Build(),
		}
	}
	return nil
}

func validateOperatorSupport(ctl *ControlDefinition) []diag.Issue {
	var issues []diag.Issue
	ctl.UnsafePredicate.Walk(func(rule PredicateRule) {
		if rule.Field.IsZero() {
			return // nested logic block, no operator to check
		}
		if !predicate.IsSupported(rule.Op) {
			issues = append(issues, diag.New(diag.CodeControlUnsupportedOperator).
				Warning().
				Action(fmt.Sprintf("Replace unsupported operator %q with a supported one", rule.Op)).
				WithMap(buildCtx(ctl, map[string]string{
					"field":    rule.Field.String(),
					"operator": string(rule.Op),
				})).
				Build())
		}
	})
	return issues
}

func validateParameterReferences(ctl *ControlDefinition) []diag.Issue {
	missing := FindMissingParamReferences(ctl.UnsafePredicate, ctl.Params)
	if len(missing) == 0 {
		return nil
	}

	issues := make([]diag.Issue, 0, len(missing))
	for _, p := range missing {
		issues = append(issues, diag.New(diag.CodeControlUndefinedParam).
			Error().
			Action(fmt.Sprintf("Add parameter '%s' to the control's 'params' section", p)).
			WithMap(buildCtx(ctl, map[string]string{"param": p})).
			Build())
	}
	return issues
}

func validateDurationConstraints(ctl *ControlDefinition) []diag.Issue {
	const key = "max_unsafe_duration"
	if !ctl.Params.HasKey(key) {
		return nil
	}

	// If the control was successfully Prepared, it's already validated.
	if ctl.Prepared.Ready && ctl.Prepared.HasMaxUnsafeDuration {
		return nil
	}

	raw := ctl.Params.String(key)
	if raw == "" {
		return []diag.Issue{
			diag.New(diag.CodeControlBadDurationParam).
				Error().
				Action("Provide a non-empty duration string (e.g., '24h', '7d')").
				WithMap(buildCtx(ctl, map[string]string{"param": key, "value": "empty"})).
				Build(),
		}
	}

	if _, err := kernel.ParseDuration(raw); err != nil {
		return []diag.Issue{
			diag.New(diag.CodeControlBadDurationParam).
				Error().
				Action("Ensure duration uses valid units: h (hours), d (days). Example: '1d12h'").
				WithMap(buildCtx(ctl, map[string]string{"param": key, "value": raw})).
				WithSensitive("error", err.Error()).
				Build(),
		}
	}

	return nil
}
