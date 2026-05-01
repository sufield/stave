package evaluation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

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
	validator     validator.RequestValidator
	validatorOnce sync.Once
	// strictSchema is read on every parseResult / LoadEnvelopeFromFile
	// call from any goroutine; WithStrictSchema is the only writer.
	// atomic.Bool removes the need to coordinate the
	// validatorOnce mutex with these reads — the previous bool field
	// was a textbook data race even though writers and readers
	// happened to be sequential in practice today.
	strictSchema atomic.Bool
}

// NewLoader returns a Loader with a default schema validator.
// The Loader is safe for concurrent use.
func NewLoader() *Loader {
	l := &Loader{}
	// Eagerly initialize through the once gate so subsequent
	// schemaValidator() calls take the fast path without entering
	// the once.Do machinery.
	l.validatorOnce.Do(func() { l.validator = validator.New() })
	return l
}

// WithStrictSchema enables JSON-schema validation on
// LoadEnvelopeFromFile against the embedded out.v0.1 schema. Required
// for trust-boundary inputs (gating, enforcement-config generation).
func (l *Loader) WithStrictSchema() *Loader {
	l.strictSchema.Store(true)
	l.validatorOnce.Do(func() { l.validator = validator.New() })
	return l
}

// schemaValidator returns the loader's validator, lazily initializing
// when the zero value Loader{} is used. Init goes through sync.Once so
// concurrent first-use callers cannot race to construct two validators
// (the cost is small, but the previous unsynchronized double-check
// pattern was a textbook race that a future heavier validator init
// — schema compilation, embedded read — would amplify into corruption).
func (l *Loader) schemaValidator() validator.RequestValidator {
	l.validatorOnce.Do(func() { l.validator = validator.New() })
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
//
// Honours WithStrictSchema by validating the bytes against the
// out.v0.1 schema before unmarshaling. The earlier shape skipped
// validation here entirely — only LoadEnvelopeFromFile checked the
// schema — so a strict-mode caller using LoadFromFile / LoadFromReader
// got the laxness of the non-strict path silently. Mirrors the
// validation logic in LoadEnvelopeFromFile.
func (l *Loader) parseResult(data []byte, source string) (*evaluation.ComplianceReport, error) {
	if l.strictSchema.Load() {
		diags, valErr := l.schemaValidator().Validate(validator.Request{
			Kind: schema.KindOutput,
			Data: data,
		})
		if valErr != nil {
			return nil, fmt.Errorf("validating evaluation %q: %w", source, valErr)
		}
		if len(diags) > 0 {
			var b strings.Builder
			b.WriteString("evaluation schema violations in ")
			b.WriteString(source)
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
func (l *Loader) LoadEnvelopeFromFile(ctx context.Context, path string) (*report.Assessment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path = fsutil.CleanUserPath(path)

	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("reading evaluation file %q: %w", path, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Schema-validate before unmarshaling into the typed struct so
	// required-field omissions produce a precise validator diagnostic
	// rather than a silent zero-valued Assessment. Opt-in (strict
	// callers must use WithStrictSchema) — this preserves backward
	// compatibility for callers feeding stub envelopes.
	if l.strictSchema.Load() {
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
func (l *Loader) LoadBaselineFromFile(ctx context.Context, path string, expectedKind kernel.OutputKind) (*evaluation.Baseline, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path = fsutil.CleanUserPath(path)

	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline file %q: %w", path, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
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
	// Format 3: Direct result ({"findings": [...]})
	// We try each shape in turn and capture the first real unmarshal
	// error so that a malformed-but-recognizable input surfaces a
	// specific JSON error instead of the generic ErrNoFindings.
	// ErrNoFindings is reserved for "no recognizable shape at all" —
	// the previous behavior conflated parse failures with structural
	// misses, hiding malformed envelopes from operators.
	var lastUnmarshalErr error

	// Format 2 takes precedence: if the document declares its kind,
	// only that shape applies. The previous structure used two
	// independent ifs and fell through to Format 3 when Format 2's
	// unmarshal failed, which masked malformed safety envelopes by
	// trying to re-parse them as a bare findings array.
	//
	// Empty findings arrays are accepted as a valid result: a clean
	// evaluation with zero violations is structurally well-formed.
	// ErrNoFindings remains reserved for "no recognizable shape at
	// all" — strict callers that want to reject empty results should
	// check len(findings) on the returned slice.
	if _, hasKind := probe["kind"]; hasKind {
		var env report.Assessment
		if err := json.Unmarshal(raw, &env); err != nil {
			lastUnmarshalErr = err
		} else {
			// Normalize nil to empty slice so callers can iterate
			// without nil-checking. PrepareBaseline and
			// BuildAssessmentFromEnriched apply the same shape.
			if env.Findings == nil {
				env.Findings = []remediation.Finding{}
			}
			return env.Findings, nil
		}
	} else if rawFindings, hasFindings := probe["findings"]; hasFindings {
		var list []remediation.Finding
		if err := json.Unmarshal(rawFindings, &list); err != nil {
			lastUnmarshalErr = err
		} else {
			if list == nil {
				list = []remediation.Finding{}
			}
			return list, nil
		}
	}

	if lastUnmarshalErr != nil {
		return nil, fmt.Errorf("failed to parse findings: %w", lastUnmarshalErr)
	}
	return nil, ErrNoFindings
}
