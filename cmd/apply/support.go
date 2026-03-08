package apply

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil"
	exemptionyaml "github.com/sufield/stave/internal/adapters/input/exemption/yaml"
	"github.com/sufield/stave/internal/domain/policy"
)

func resolveApplyContextName(projectRoot string) string {
	if sc, err := cmdutil.ResolveSelectedGlobalContext(); err == nil && sc.Active && strings.TrimSpace(sc.Name) != "" {
		return strings.TrimSpace(sc.Name)
	}
	base := filepath.Base(projectRoot)
	if strings.TrimSpace(base) == "" || base == "." || base == string(os.PathSeparator) {
		return "default"
	}
	return base
}

func loadExemptionConfig(path string) (*policy.ExemptionConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	cfg, err := exemptionyaml.LoadExemptionConfig(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load ignore file: %w", err)
	}
	return cfg, nil
}
