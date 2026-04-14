// Package acknowledgment loads acknowledgment config from YAML files.
package acknowledgment

import (
	"fmt"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

type yamlAcknowledgmentConfig struct {
	Acknowledgments []policy.AcknowledgmentRule `yaml:"acknowledgments"`
}

// Load reads an acknowledgment config from a YAML file.
func Load(path string) (*policy.AcknowledgmentConfig, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("reading acknowledgment file %q: %w", path, err)
	}

	var cfg yamlAcknowledgmentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing acknowledgment YAML from %q: %w", path, err)
	}

	return policy.NewAcknowledgmentConfig(cfg.Acknowledgments), nil
}
