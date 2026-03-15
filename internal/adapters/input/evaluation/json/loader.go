package json

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
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
