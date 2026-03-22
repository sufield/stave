package validate

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/pkg/alpha/domain/diag"
)

// PackConfigIssues checks for unknown control pack names in the project config.
func PackConfigIssues() []diag.Issue {
	cfg, ok, cfgErr := projconfig.FindProjectConfig()
	if cfgErr != nil {
		return []diag.Issue{
			diag.New(diag.CodeProjectConfigLoadFailed).
				Error().
				Action("Check stave.yaml for syntax errors").
				WithSensitive("error", cfgErr.Error()).
				Build(),
		}
	}
	if !ok || len(cfg.EnabledControlPacks) == 0 {
		return nil
	}
	reg, err := packs.NewEmbeddedRegistry()
	if err != nil {
		return []diag.Issue{
			diag.New(diag.CodePackRegistryLoadFailed).
				Error().
				Action("Reinstall Stave binary or verify embedded registry integrity").
				WithSensitive("error", err.Error()).
				Build(),
		}
	}
	known := reg.PackNames()
	knownSet := make(map[string]struct{}, len(known))
	for _, name := range known {
		knownSet[name] = struct{}{}
	}
	var issues []diag.Issue
	for _, raw := range cfg.EnabledControlPacks {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if _, ok := knownSet[name]; ok {
			continue
		}
		issues = append(issues, diag.New(diag.CodeUnknownControlPack).
			Error().
			Action(fmt.Sprintf("Use a configured pack name: %s", strings.Join(known, ", "))).
			With("pack", name).
			Build())
	}
	return issues
}
