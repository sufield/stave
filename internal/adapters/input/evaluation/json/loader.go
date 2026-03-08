package json

import (
	"encoding/json"
	"fmt"
	"io"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/safetyenvelope"
)

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
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load output file %s: %w", path, err)
	}

	var result evaluation.Result
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to load output file %s: invalid JSON: %w", path, err)
	}

	return &result, nil
}

// ParseFindings extracts remediation findings from JSON data, trying multiple
// envelope formats: safety envelope, wrapped envelope, bare findings array.
func ParseFindings(raw []byte) ([]remediation.Finding, error) {
	var env safetyenvelope.Evaluation
	if err := json.Unmarshal(raw, &env); err == nil && len(env.Findings) > 0 {
		return env.Findings, nil
	}

	var wrapped struct {
		OK   bool                      `json:"ok"`
		Data safetyenvelope.Evaluation `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil && len(wrapped.Data.Findings) > 0 {
		return wrapped.Data.Findings, nil
	}

	var direct struct {
		Findings []remediation.Finding `json:"findings"`
	}
	if err := json.Unmarshal(raw, &direct); err == nil {
		return direct.Findings, nil
	}

	var probe any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("input JSON does not contain evaluation findings")
}

// LoadFromReader loads an evaluation result from an io.Reader.
func (l *Loader) LoadFromReader(r io.Reader, sourceName string) (*evaluation.Result, error) {
	data, err := fsutil.LimitedReadAll(r, sourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to read evaluation output from %s: %w", sourceName, err)
	}

	var result evaluation.Result
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse evaluation output from %s: invalid JSON: %w", sourceName, err)
	}

	return &result, nil
}
