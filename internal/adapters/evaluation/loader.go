package evaluation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/internal/contracts/schema"
	"github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// ErrNoFindings is returned when input JSON does not contain evaluation findings.
var ErrNoFindings = errors.New("input JSON does not contain evaluation findings")

// Loader reads evaluation result artifacts from JSON.
//
// Schema validation is opt-in via WithStrictSchema. Trust-boundary
// callers (gating, enforcement generation) should opt in so a forged
// `{"kind":"ASSESSMENT","findings":[]}` cannot drive a "clean"
// verdict — schema rejection catches missing required fields before
// any consumer reads .Findings. Looser callers (diff display,
// historical baselines) can keep the default lax behavior to stay
// compatible with stub fixtures.
type Loader struct {
	validator    *validator.Validator
	strictSchema bool
}

// NewLoader returns a Loader with a default schema validator.
// The Loader is safe for concurrent use.
func NewLoader() *Loader {
	return &Loader{validator: validator.New()}
}

// WithStrictSchema enables JSON-schema validation on
// LoadEnvelopeFromFile against the embedded out.v0.1 schema. Required
// for trust-boundary inputs (gating, enforcement-config generation).
func (l *Loader) WithStrictSchema() *Loader {
	l.strictSchema = true
	if l.validator == nil {
		l.validator = validator.New()
	}
	return l
}

// schemaValidator returns the loader's validator, lazily initializing
// when the zero value Loader{} is used. Callers passing &Loader{} keep
// working without changes — the validator is created on first use.
func (l *Loader) schemaValidator() *validator.Validator {
	if l.validator == nil {
		l.validator = validator.New()
	}
	return l.validator
}

// LoadFromFile loads an evaluation result from a JSON file.
func (l *Loader) LoadFromFile(path string) (*evaluation.ComplianceReport, error) {
	path = fsutil.CleanUserPath(path)
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load output file %q: %w", path, err)
	}
	return l.parseResult(data, path)
}

// LoadFromReader loads an evaluation result from an io.Reader.
func (l *Loader) LoadFromReader(r io.Reader, sourceName string) (*evaluation.ComplianceReport, error) {
	data, err := fsutil.LimitedReadAll(r, sourceName)
	if err != nil {
		return nil, fmt.Errorf("reading evaluation from %s: %w", sourceName, err)
	}
	return l.parseResult(data, sourceName)
}

// parseResult is the shared unmarshaling path for both file and reader loading.
func (l *Loader) parseResult(data []byte, source string) (*evaluation.ComplianceReport, error) {
	var result evaluation.ComplianceReport
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to load output file %s: invalid JSON: %w", source, err)
	}
	return &result, nil
}

// LoadEnvelopeFromFile loads and validates a JSON safety envelope
// containing evaluation results. The artifact is validated against
// the embedded out.v0.1 JSON schema (kind=output) BEFORE any
// downstream code reads .Findings, so a hand-crafted JSON like
// `{"kind":"ASSESSMENT","findings":[]}` cannot drive remediation /
// gating into a "clean" verdict — it fails schema validation on
// missing required fields (schema_version, run, summary, status).
func (l *Loader) LoadEnvelopeFromFile(_ context.Context, path string) (*report.Assessment, error) {
	path = fsutil.CleanUserPath(path)

	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("reading evaluation file %q: %w", path, err)
	}

	// Schema-validate before unmarshaling into the typed struct so
	// required-field omissions produce a precise validator diagnostic
	// rather than a silent zero-valued Assessment. Opt-in (strict
	// callers must use WithStrictSchema) — this preserves backward
	// compatibility for callers feeding stub envelopes.
	if l.strictSchema {
		diags, valErr := l.schemaValidator().Validate(validator.Request{
			Kind: schema.KindOutput,
			Data: data,
		})
		if valErr != nil {
			return nil, fmt.Errorf("validating evaluation %q: %w", path, valErr)
		}
		if len(diags) > 0 {
			var b strings.Builder
			b.WriteString("evaluation schema violations in ")
			b.WriteString(path)
			b.WriteString(":")
			for i, d := range diags {
				if i >= 5 {
					fmt.Fprintf(&b, "\n  ... (+%d more)", len(diags)-5)
					break
				}
				fmt.Fprintf(&b, "\n  %s: %s", d.Path, d.Message)
			}
			return nil, fmt.Errorf("%s: %w", b.String(), validator.ErrSchemaValidationFailed)
		}
	}

	var eval report.Assessment
	if err := json.Unmarshal(data, &eval); err != nil {
		return nil, fmt.Errorf("parsing evaluation JSON from %q: %w", path, err)
	}

	if eval.Kind != report.KindAssessment {
		return nil, fmt.Errorf("invalid artifact kind in %q: got %q, expected %q",
			path, eval.Kind, report.KindAssessment)
	}

	return &eval, nil
}

// LoadBaselineFromFile loads a baseline finding file and ensures findings are sorted deterministically.
func (l *Loader) LoadBaselineFromFile(_ context.Context, path string, expectedKind kernel.OutputKind) (*evaluation.Baseline, error) {
	path = fsutil.CleanUserPath(path)

	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline file %q: %w", path, err)
	}

	var base evaluation.Baseline
	if err := json.Unmarshal(data, &base); err != nil {
		return nil, fmt.Errorf("parsing baseline JSON from %q: %w", path, err)
	}

	if err := PrepareBaseline(&base, expectedKind, path); err != nil {
		return nil, err
	}
	return &base, nil
}

// PrepareBaseline validates and normalizes a deserialized baseline for use.
// It checks the kind field, initializes nil slices, and sorts findings deterministically.
func PrepareBaseline(base *evaluation.Baseline, expectedKind kernel.OutputKind, source string) error {
	if base.Kind != expectedKind {
		return fmt.Errorf("invalid baseline kind in %q: got %q, expected %q",
			source, base.Kind, expectedKind)
	}
	if base.Findings == nil {
		base.Findings = []evaluation.BaselineEntry{}
	}
	evaluation.SortBaselineEntries(base.Findings)
	return nil
}

// ParseFindings extracts findings from various JSON envelope formats.
// It probes the top-level keys to identify the format before performing
// a full unmarshal, avoiding trial-and-error deserialization.
//
// Supported formats:
//   - API wrapped envelope: {"ok": true, "data": {"findings": [...]}}
//   - Safety envelope:      {"kind": "evaluation", "findings": [...]}
//   - Direct result:        {"findings": [...]}
func ParseFindings(raw []byte) ([]remediation.Finding, error) {
	return parseFindings(raw, 0)
}

// maxFindingsEnvelopeDepth bounds the recursion through nested
// `{"ok":..., "data":{...}}` API envelopes. Real producers wrap at
// most once; deeper nesting is either a malformed file or an
// adversarial input designed to consume stack via unbounded recursion.
const maxFindingsEnvelopeDepth = 3

func parseFindings(raw []byte, depth int) ([]remediation.Finding, error) {
	if depth > maxFindingsEnvelopeDepth {
		return nil, fmt.Errorf("findings envelope nested deeper than %d levels", maxFindingsEnvelopeDepth)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Format 1: API wrapped envelope ({"ok": ..., "data": {...}})
	if _, hasOK := probe["ok"]; hasOK {
		if data, hasData := probe["data"]; hasData {
			return parseFindings(data, depth+1)
		}
	}

	// Format 2: Safety envelope ({"kind": ..., "findings": [...]})
	if _, hasKind := probe["kind"]; hasKind {
		var env report.Assessment
		if err := json.Unmarshal(raw, &env); err == nil {
			return env.Findings, nil
		}
	}

	// Format 3: Direct result ({"findings": [...]})
	if rawFindings, hasFindings := probe["findings"]; hasFindings {
		var list []remediation.Finding
		if err := json.Unmarshal(rawFindings, &list); err == nil {
			return list, nil
		}
	}

	return nil, ErrNoFindings
}
