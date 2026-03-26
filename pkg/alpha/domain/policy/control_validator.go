package policy

import (
	"fmt"
	"maps"
	"strings"

	"github.com/sufield/stave/pkg/alpha/domain/diag"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/predicate"
)

// validationRule defines a functional signature for checking specific aspects of a control.
type validationRule func(*ControlDefinition) []diag.Issue

// ValidateControlDefinition performs a comprehensive logical and structural
// audit of a control's configuration.
func ValidateControlDefinition(ctl *ControlDefinition) []diag.Issue {
	if ctl == nil {
		return nil
	}

	// Define the pipeline of rules. Order matters if one check depends on another,
	// though these are designed to be mostly independent.
	rules := []validationRule{
		validateRequiredMetadata,
		validateIdentityFormat,
		validateSeverityLevel,
		validateControlCategory,
		validatePredicateStructure,
		validateOperatorAvailability,
		validateParameterIntegrity,
		validateTemporalConstraints,
	}

	var issues []diag.Issue
	for _, rule := range rules {
		if found := rule(ctl); len(found) > 0 {
			issues = append(issues, found...)
		}
	}
	return issues
}

// buildIssueContext generates the standard diagnostic evidence map.
func buildIssueContext(ctl *ControlDefinition, extra map[string]string) map[string]string {
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

// validateRequiredMetadata ensures the control has the basic identifying info.
func validateRequiredMetadata(ctl *ControlDefinition) []diag.Issue {
	var issues []diag.Issue
	ctx := buildIssueContext(ctl, nil)

	if ctl.ID == "" {
		issues = append(issues, diag.New(diag.CodeControlMissingID).
			Error().
			Action("Add a unique 'id' (e.g., CTL.S3.PUBLIC.001) to the control definition").
			WithMap(ctx).
			Build())
	}

	if strings.TrimSpace(ctl.Name) == "" {
		issues = append(issues, diag.New(diag.CodeControlMissingName).
			Error().
			Action("Assign a descriptive 'name' to the control for reporting").
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

// validateIdentityFormat checks if the ID matches the kernel's naming convention.
func validateIdentityFormat(ctl *ControlDefinition) []diag.Issue {
	if ctl.ID == "" {
		return nil
	}

	if err := kernel.ValidateControlIDFormat(ctl.ID.String()); err != nil {
		return []diag.Issue{
			diag.New(diag.CodeControlBadIDFormat).
				Warning().
				Action("Align ID with standard format: CTL.<PROVIDER>.<CATEGORY>.<SEQ>").
				WithMap(buildIssueContext(ctl, nil)).
				WithSensitive("error", err.Error()).
				Build(),
		}
	}
	return nil
}

// validateSeverityLevel ensures the severity is within the supported enum range.
func validateSeverityLevel(ctl *ControlDefinition) []diag.Issue {
	if ctl.Severity == SeverityNone || ctl.Severity.IsValid() {
		return nil
	}

	return []diag.Issue{
		diag.New(diag.CodeControlBadSeverity).
			Warning().
			Action("Use a valid severity: info, low, medium, high, or critical").
			WithMap(buildIssueContext(ctl, map[string]string{"severity": ctl.Severity.String()})).
			Build(),
	}
}

// validateControlCategory ensures the control logic type is recognized.
func validateControlCategory(ctl *ControlDefinition) []diag.Issue {
	if ctl.Type == TypeUnknown || ctl.Type.IsValid() {
		return nil
	}

	return []diag.Issue{
		diag.New(diag.CodeControlBadType).
			Warning().
			Action("Specify a supported control type (e.g., unsafe_state, unsafe_duration)").
			WithMap(buildIssueContext(ctl, map[string]string{"type": ctl.Type.String()})).
			Build(),
	}
}

// validatePredicateStructure ensures the logic tree isn't empty.
func validatePredicateStructure(ctl *ControlDefinition) []diag.Issue {
	if len(ctl.UnsafePredicate.Any) == 0 && len(ctl.UnsafePredicate.All) == 0 {
		return []diag.Issue{
			diag.New(diag.CodeControlEmptyPredicate).
				Warning().
				Action("Define at least one rule under 'any' or 'all' in the unsafe_predicate").
				WithMap(buildIssueContext(ctl, nil)).
				Build(),
		}
	}
	return nil
}

// validateOperatorAvailability checks if the logic operators exist in the engine.
func validateOperatorAvailability(ctl *ControlDefinition) []diag.Issue {
	var issues []diag.Issue

	// We use the Walk method defined in previous steps to visit all nodes.
	ctl.UnsafePredicate.Walk(func(rule PredicateRule) {
		// A rule with no field is a logical wrapper (any/all), skip it.
		if rule.Field.IsZero() {
			return
		}

		if !predicate.IsSupported(rule.Op) {
			issues = append(issues, diag.New(diag.CodeControlUnsupportedOperator).
				Warning().
				Action(fmt.Sprintf("Replace unsupported operator %q with a valid one (eq, ne, in, etc.)", rule.Op)).
				WithMap(buildIssueContext(ctl, map[string]string{
					"field":    rule.Field.String(),
					"operator": string(rule.Op),
				})).
				Build())
		}
	})
	return issues
}

// validateParameterIntegrity ensures all 'ValueFromParam' entries exist in the params map.
func validateParameterIntegrity(ctl *ControlDefinition) []diag.Issue {
	missing := ctl.UnsafePredicate.MissingParamReferences(ctl.Params)
	if len(missing) == 0 {
		return nil
	}

	issues := make([]diag.Issue, 0, len(missing))
	for _, p := range missing {
		issues = append(issues, diag.New(diag.CodeControlUndefinedParam).
			Error().
			Action(fmt.Sprintf("Define parameter %q in the control's 'params' section", p)).
			WithMap(buildIssueContext(ctl, map[string]string{"param": p})).
			Build())
	}
	return issues
}

// validateTemporalConstraints checks if max_unsafe_duration is a valid duration string.
func validateTemporalConstraints(ctl *ControlDefinition) []diag.Issue {
	const durationKey = "max_unsafe_duration"

	if !ctl.Params.HasKey(durationKey) {
		return nil
	}

	// Optimization: If the control state indicates it's already prepared/validated, skip.
	if ctl.Prepared.Ready && ctl.Prepared.HasMaxUnsafeDuration {
		return nil
	}

	raw := ctl.Params.paramString(durationKey)
	if raw == "" {
		return []diag.Issue{
			diag.New(diag.CodeControlBadDurationParam).
				Error().
				Action("Provide a valid duration (e.g., '30d') for max_unsafe_duration").
				WithMap(buildIssueContext(ctl, map[string]string{"param": durationKey})).
				Build(),
		}
	}

	if _, err := kernel.ParseDuration(raw); err != nil {
		return []diag.Issue{
			diag.New(diag.CodeControlBadDurationParam).
				Error().
				Action("Use valid duration units: 'h' for hours or 'd' for days").
				WithMap(buildIssueContext(ctl, map[string]string{"param": durationKey, "value": raw})).
				WithSensitive("error", err.Error()).
				Build(),
		}
	}

	return nil
}
