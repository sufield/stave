package policy

import (
	"fmt"
	"maps"
	"strings"

	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/domain/kernel"
)

// ValidateControlDefinition checks a single control definition for errors and warnings.
func ValidateControlDefinition(ctl *ControlDefinition) []diag.Issue {
	if ctl == nil {
		return nil
	}
	return validate(ctl)
}

// validate checks a single control definition for errors and warnings.
func validate(ctl *ControlDefinition) []diag.Issue {
	var issues []diag.Issue
	issues = append(issues, validateRequiredFields(ctl)...)
	issues = append(issues, validateIDFormat(ctl)...)
	issues = append(issues, validateSeverity(ctl)...)
	issues = append(issues, validateType(ctl)...)
	issues = append(issues, validatePredicate(ctl)...)
	issues = append(issues, validateParamReferences(ctl)...)
	issues = append(issues, validateMaxUnsafeDuration(ctl)...)
	return issues
}

// controlCtx builds an evidence map with control_id and description,
// plus any additional key-value pairs.
func controlCtx(ctl *ControlDefinition, extra map[string]string) map[string]string {
	m := make(map[string]string, len(extra)+2)
	if ctl.ID != "" {
		m["control_id"] = ctl.ID.String()
	}
	if desc := strings.TrimSpace(ctl.Description); desc != "" {
		m["description"] = desc
	}
	maps.Copy(m, extra)
	return m
}

func validateRequiredFields(ctl *ControlDefinition) []diag.Issue {
	issues := make([]diag.Issue, 0, 3)
	ctx := controlCtx(ctl, nil)

	if ctl.ID == "" {
		issues = append(issues, diag.New(diag.CodeControlMissingID).
			Error().
			Action("Add 'id: CTL.<DOMAIN>.<CATEGORY>.<SEQ>' to the control YAML").
			WithMap(ctx).
			Build())
	}

	if strings.TrimSpace(ctl.Name) == "" {
		issues = append(issues, diag.New(diag.CodeControlMissingName).
			Error().
			Action("Add 'name: <descriptive name>' to the control YAML").
			WithMap(ctx).
			Build())
	}

	if strings.TrimSpace(ctl.Description) == "" {
		issues = append(issues, diag.New(diag.CodeControlMissingDesc).
			Error().
			Action("Add 'description: <what this control checks>' to the control YAML").
			WithMap(ctx).
			Build())
	}

	return issues
}

func validateSeverity(ctl *ControlDefinition) []diag.Issue {
	if ctl.Severity == SeverityNone || ctl.Severity.IsValid() {
		return nil
	}

	return []diag.Issue{
		diag.New(diag.CodeControlBadSeverity).
			Warning().
			Action("Use a valid severity: info, low, medium, high, critical").
			WithMap(controlCtx(ctl, map[string]string{
				"severity": ctl.Severity.String(),
			})).
			Build(),
	}
}

func validateIDFormat(ctl *ControlDefinition) []diag.Issue {
	if ctl.ID == "" {
		return nil
	}

	err := kernel.ValidateControlIDFormat(ctl.ID.String())
	if err == nil {
		return nil
	}

	return []diag.Issue{
		diag.New(diag.CodeControlBadIDFormat).
			Warning().
			Action("Use format CTL.<DOMAIN>.<CATEGORY>.<SEQ> (e.g., CTL.S3.PUBLIC.001)").
			WithMap(controlCtx(ctl, nil)).
			WithSensitive("error", err.Error()).
			Build(),
	}
}

func validateType(ctl *ControlDefinition) []diag.Issue {
	if ctl.Type == TypeUnknown || ctl.Type.IsValid() {
		return nil
	}

	return []diag.Issue{
		diag.New(diag.CodeControlBadType).
			Warning().
			Action("Use a canonical type: unsafe_state, unsafe_duration, unsafe_recurrence, authorization_boundary, audience_boundary, justification_required, ownership_required, visibility_required, prefix_exposure").
			WithMap(controlCtx(ctl, map[string]string{
				"type": ctl.Type.String(),
			})).
			Build(),
	}
}

func validatePredicate(ctl *ControlDefinition) []diag.Issue {
	if len(ctl.UnsafePredicate.Any) > 0 || len(ctl.UnsafePredicate.All) > 0 {
		return nil
	}

	return []diag.Issue{
		diag.New(diag.CodeControlEmptyPredicate).
			Warning().
			Action("Add 'unsafe_predicate: any: [...]' or 'unsafe_predicate: all: [...]' rules").
			WithMap(controlCtx(ctl, nil)).
			Build(),
	}
}

func validateParamReferences(ctl *ControlDefinition) []diag.Issue {
	missingParams := FindMissingParamReferences(ctl.UnsafePredicate, ctl.Params)
	if len(missingParams) == 0 {
		return nil
	}

	issues := make([]diag.Issue, 0, len(missingParams))
	for _, param := range missingParams {
		issues = append(issues, diag.New(diag.CodeControlUndefinedParam).
			Error().
			Action(fmt.Sprintf("Add '%s' to the control's params section", param)).
			WithMap(controlCtx(ctl, map[string]string{
				"param": param,
			})).
			Build())
	}
	return issues
}

func validateMaxUnsafeDuration(ctl *ControlDefinition) []diag.Issue {
	const paramName = "max_unsafe_duration"
	if !ctl.Params.HasKey(paramName) {
		return nil
	}

	raw := ctl.Params.String(paramName)
	if raw == "" {
		return []diag.Issue{
			diag.New(diag.CodeControlBadDurationParam).
				Error().
				Action("Set max_unsafe_duration to a valid duration string (e.g., '0h', '24h', '7d')").
				WithMap(controlCtx(ctl, map[string]string{
					"param": paramName,
					"value": fmt.Sprintf("%v", ctl.Params[paramName]),
				})).
				Build(),
		}
	}

	// If Prepare() already validated this parameter successfully, skip re-parse.
	if ctl.Prepared.Ready && ctl.Prepared.HasMaxUnsafeDuration {
		return nil
	}

	_, err := kernel.ParseDuration(raw)
	if err == nil {
		return nil
	}

	return []diag.Issue{
		diag.New(diag.CodeControlBadDurationParam).
			Error().
			Action("Fix max_unsafe_duration value (use format: 0h, 24h, 7d, 1d12h)").
			WithMap(controlCtx(ctl, map[string]string{
				"param": paramName,
				"value": raw,
			})).
			WithSensitive("error", err.Error()).
			Build(),
	}
}
