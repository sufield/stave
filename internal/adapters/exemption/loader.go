package exemption

import (
	"fmt"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

// Loader handles retrieval of exemption configurations from YAML files.
type Loader struct{}

// Load reads and parses an exemption configuration from the given path.
// It normalizes the path and wraps errors with file context for diagnostics.
func (l *Loader) Load(path string) (*policy.ExemptionConfig, error) {
	cleanPath := fsutil.CleanUserPath(path)

	data, err := fsutil.ReadFileLimited(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("reading exemption file %q: %w", cleanPath, err)
	}

	var dto yamlExemptionConfig
	if unmarshalErr := yaml.Unmarshal(data, &dto); unmarshalErr != nil {
		return nil, fmt.Errorf("malformed YAML in exemption file %q: %w", cleanPath, unmarshalErr)
	}

	cfg, err := exemptionConfigToDomain(dto)
	if err != nil {
		return nil, fmt.Errorf("invalid exemption file %q: %w", cleanPath, err)
	}
	return cfg, nil
}
