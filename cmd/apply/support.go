package apply

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil"
	exemptionyaml "github.com/sufield/stave/internal/adapters/input/exemption/yaml"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/domain/policy"
)

// attachRunIDFromPlan derives a run ID from the evaluation plan and sets it on
// the default logger.
func attachRunIDFromPlan(plan *appeval.EvaluationPlan) {
	if plan == nil {
		return
	}
	attachRunID(strings.TrimSpace(plan.ObservationsHash.String()), strings.TrimSpace(plan.ControlsHash.String()))
}

// attachRunID computes a run ID from input hashes and sets it on the default logger.
func attachRunID(inputsHash, controlsHash string) {
	cmdutil.AttachRunID(inputsHash, controlsHash)
}

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
