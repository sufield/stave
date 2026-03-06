package json

import (
	"encoding/json"
	"fmt"
	"io"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/platform/fsutil"
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
