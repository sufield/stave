package apply

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	exemptionyaml "github.com/sufield/stave/internal/adapters/input/exemption/yaml"
	"github.com/sufield/stave/internal/domain/policy"
)

// ResolveContextName provides the default logic for naming the evaluation run.
// It is pure — it doesn't look at global state, only its inputs.
func ResolveContextName(projectRoot string, selectedContext string) string {
	if strings.TrimSpace(selectedContext) != "" {
		return strings.TrimSpace(selectedContext)
	}

	base := filepath.Base(projectRoot)
	if base == "" || base == "." || base == string(os.PathSeparator) {
		return "default"
	}
	return base
}

// LoadExemptionConfig loads and wraps domain-level exemptions from a YAML file.
func LoadExemptionConfig(path string) (*policy.ExemptionConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	cfg, err := exemptionyaml.LoadExemptionConfig(path)
	if err != nil {
		return nil, fmt.Errorf("loading exemptions from %q: %w", path, err)
	}
	return cfg, nil
}
