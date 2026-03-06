package yaml

import (
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

// LoadExemptionConfig loads an asset exemption configuration from a YAML file.
func LoadExemptionConfig(path string) (*policy.ExemptionConfig, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, err
	}

	var config policy.ExemptionConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
