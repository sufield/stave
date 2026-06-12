package validatecmd

import (
	"bytes"
	"fmt"

	appvalidation "github.com/sufield/stave/internal/app/validation"
	schemas "github.com/sufield/stave/internal/contracts/schema"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
)

// canonicalKinds maps the canonical kind strings — resolved command-side from
// user aliases via ui.NormalizeToken — to schema kinds.
var canonicalKinds = map[string]schemas.Kind{
	"control":     schemas.KindControl,
	"observation": schemas.KindObservation,
	"finding":     schemas.KindFinding,
}

// ValidateContent validates a single input document (the --in path) and
// renders the report. kind is the canonical kind string ("control",
// "observation", or "finding") resolved command-side, or "" for
// auto-detection. controlsDir/observationsDir feed fix-hint generation.
func ValidateContent(
	data []byte,
	kind, schemaVersion string,
	strict bool,
	format, template string,
	fixHints bool,
	controlsDir, observationsDir string,
	label LabelFunc,
	tmpl TemplateFunc,
) (Result, error) {
	var req appvalidation.ContentValidator
	if kind == "" {
		req = appvalidation.AutoRequest{Data: data}
	} else {
		k, ok := canonicalKinds[kind]
		if !ok {
			return Result{}, fmt.Errorf("unknown content kind %q", kind)
		}
		req = appvalidation.ExplicitRequest{
			Data:          data,
			Kind:          k,
			SchemaVersion: schemaVersion,
			Strict:        strict,
		}
	}

	service := appvalidation.NewContentService(func() contractvalidator.SchemaValidator { return contractvalidator.New() })
	result, err := service.Validate(req)
	if err != nil {
		return Result{}, fmt.Errorf("validation failed: %w", err)
	}

	var buf bytes.Buffer
	rep := &Reporter{
		Writer:   &buf,
		Format:   renderFormatStr(format, template),
		Strict:   strict,
		FixHints: fixHints,
		Label:    label,
		Template: tmpl,
	}
	hc := hintContext{ControlsDir: controlsDir, ObservationsDir: observationsDir}
	if err := rep.Write(result, hc); err != nil {
		return Result{}, err
	}
	return Result{Output: buf.Bytes(), ExitErr: rep.ExitStatus(result)}, nil
}
