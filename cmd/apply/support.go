package apply

import (
	"fmt"
	"strings"

	exemptionyaml "github.com/sufield/stave/internal/adapters/input/exemption/yaml"
	appapply "github.com/sufield/stave/internal/app/apply"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// ResolveContextName provides the default logic for naming the evaluation run.
var ResolveContextName = appapply.ResolveContextName

// LoadExemptionConfig loads and wraps domain-level exemptions from a YAML file.
func LoadExemptionConfig(path string) (*policy.ExemptionConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	cfg, err := exemptionyaml.NewLoader().Load(path)
	if err != nil {
		return nil, fmt.Errorf("loading exemptions from %q: %w", path, err)
	}
	return cfg, nil
}
