package json

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// ErrNoFindings is returned when input JSON does not contain evaluation findings.
var ErrNoFindings = errors.New("input JSON does not contain evaluation findings")

// Loader reads evaluation result artifacts from JSON.
type Loader struct{}

var (
	_ appcontracts.FileResultLoader   = (*Loader)(nil)
	_ appcontracts.ReaderResultLoader = (*Loader)(nil)
	_ appcontracts.FileEnvelopeLoader = (*Loader)(nil)
	_ appcontracts.FileBaselineLoader = (*Loader)(nil)
)

// NewLoader creates a new evaluation result JSON loader.
func NewLoader() *Loader {
	return &Loader{}
}

// LoadFromFile loads an evaluation result from a JSON file.
func (l *Loader) LoadFromFile(path string) (*evaluation.Result, error) {
	path = fsutil.CleanUserPath(path)
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load output file %q: %w", path, err)
	}
	return l.parseResult(data, path)
}

// LoadFromReader loads an evaluation result from an io.Reader.
func (l *Loader) LoadFromReader(r io.Reader, sourceName string) (*evaluation.Result, error) {
	data, err := fsutil.LimitedReadAll(r, sourceName)
	if err != nil {
		return nil, fmt.Errorf("reading evaluation from %s: %w", sourceName, err)
	}
	return l.parseResult(data, sourceName)
}

// parseResult is the shared unmarshaling path for both file and reader loading.
func (l *Loader) parseResult(data []byte, source string) (*evaluation.Result, error) {
	var result evaluation.Result
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to load output file %s: invalid JSON: %w", source, err)
	}
	return &result, nil
}

// LoadEnvelopeFromFile loads and validates a JSON safety envelope containing evaluation results.
func (l *Loader) LoadEnvelopeFromFile(path string) (*safetyenvelope.Evaluation, error) {
	path = fsutil.CleanUserPath(path)

	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("reading evaluation file %q: %w", path, err)
	}

	var eval safetyenvelope.Evaluation
	if err := json.Unmarshal(data, &eval); err != nil {
		return nil, fmt.Errorf("parsing evaluation JSON from %q: %w", path, err)
	}

	if eval.Kind != safetyenvelope.KindEvaluation {
		return nil, fmt.Errorf("invalid artifact kind in %q: got %q, expected %q",
			path, eval.Kind, safetyenvelope.KindEvaluation)
	}

	return &eval, nil
}

// LoadBaselineFromFile loads a baseline finding file and ensures findings are sorted deterministically.
func (l *Loader) LoadBaselineFromFile(path string, expectedKind kernel.OutputKind) (*evaluation.Baseline, error) {
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
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Format 1: API wrapped envelope ({"ok": ..., "data": {...}})
	if _, hasOK := probe["ok"]; hasOK {
		if data, hasData := probe["data"]; hasData {
			return ParseFindings(data)
		}
	}

	// Format 2: Safety envelope ({"kind": ..., "findings": [...]})
	if _, hasKind := probe["kind"]; hasKind {
		var env safetyenvelope.Evaluation
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
