package stave

import (
	"context"

	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/pkg/stave/internal/validatecmd"
)

// ValidateProjectRequest is the parsed input for project validation.
type ValidateProjectRequest = validatecmd.Request

// ValidateProjectResult is the rendered outcome of validation.
type ValidateProjectResult = validatecmd.Result

// LabelFunc formats a severity label for text output (backed by
// ui.SeverityLabel command-side, since pkg/stave cannot import cli/ui).
type LabelFunc = validatecmd.LabelFunc

// TemplateFunc renders a report through a template file (backed by
// ui.ExecuteTemplate command-side).
type TemplateFunc = validatecmd.TemplateFunc

// ValidateProject runs full project validation — the default `stave validate`
// path: parse params, validate controls + observations against the builtin
// catalog fallback, fold in unknown-pack diagnostics, render to bytes, and
// apply the optional --assert-recent staleness assertion.
//
// enabledPacks + packConfigLoadErr come from command-side stave.yaml
// discovery (a cmd-layer concern); the library turns them into pack
// diagnostics. label/tmpl inject the cli/ui-bound formatting.
func ValidateProject(
	ctx context.Context,
	req ValidateProjectRequest,
	enabledPacks []string,
	packConfigLoadErr string,
	label LabelFunc,
	tmpl TemplateFunc,
) (ValidateProjectResult, error) {
	packIssues := packConfigDiagnostics(enabledPacks, packConfigLoadErr)
	return validatecmd.Run(ctx, req, label, tmpl, packIssues) //nolint:wrapcheck // engine already wraps; preserve exit-code sentinels (ErrValidationFailed/Warnings).
}

// ValidateContent validates a single document (the `stave validate --in`
// path). kind is the canonical kind string resolved command-side, or "" for
// auto-detection.
func ValidateContent(
	data []byte,
	kind, schemaVersion string,
	strict bool,
	format, template string,
	fixHints bool,
	controlsDir, observationsDir string,
	label LabelFunc,
	tmpl TemplateFunc,
) (ValidateProjectResult, error) {
	return validatecmd.ValidateContent(data, kind, schemaVersion, strict, format, template, fixHints, controlsDir, observationsDir, label, tmpl) //nolint:wrapcheck // engine already wraps; preserve exit-code sentinels.
}

// packConfigDiagnostics builds the pack-config findings: a load-failure
// finding when stave.yaml could not be read, otherwise the unknown-pack
// registry check. Mirrors projconfig.PackConfigIssues (which keeps the
// stave.yaml discovery on the command side).
func packConfigDiagnostics(enabledPacks []string, loadErr string) []diag.Finding {
	if loadErr != "" {
		return []diag.Finding{
			diag.NewFinding(diag.RuleProjectConfigLoadFailed).
				Error().
				Remediation("Check stave.yaml for syntax errors").
				SensitiveAttribute("error", loadErr).
				Build(),
		}
	}
	return ValidatePackConfiguration(enabledPacks)
}
