package exemption

import (
	"fmt"

	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
	"gopkg.in/yaml.v3"
)

// Loader handles retrieval of exemption configurations from YAML files.
type Loader struct{}

// NewLoader initializes a standard YAML exemption loader.
func NewLoader() *Loader {
	return &Loader{}
}

// Load reads and parses an exemption configuration from the given path.
// It normalizes the path and wraps errors with file context for diagnostics.
func (l *Loader) Load(path string) (*policy.ExemptionConfig, error) {
	cleanPath := fsutil.CleanUserPath(path)

	data, err := fsutil.ReadFileLimited(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("reading exemption file %q: %w", cleanPath, err)
	}

	var dto yamlExemptionConfig
	if err := yaml.Unmarshal(data, &dto); err != nil {
		return nil, fmt.Errorf("malformed YAML in exemption file %q: %w", cleanPath, err)
	}

	cfg := exemptionConfigToDomain(dto)
	return &cfg, nil
}
