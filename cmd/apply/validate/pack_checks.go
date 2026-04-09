package validate

import (
	"strings"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/core/diag"
)

// PackConfigIssues checks for unknown control pack names in the project config.
func PackConfigIssues() []diag.Finding {
	cfg, ok, cfgErr := projconfig.FindProjectConfig()
	if cfgErr != nil {
		return []diag.Finding{
			diag.NewFinding(diag.RuleProjectConfigLoadFailed).
				Error().
				Remediation("Check stave.yaml for syntax errors").
				SensitiveAttribute("error", cfgErr.Error()).
				Build(),
		}
	}
	if !ok || len(cfg.EnabledControlPacks) == 0 {
		return nil
	}
	reg, err := packs.NewEmbeddedRegistry()
	if err != nil {
		return []diag.Finding{
			diag.NewFinding(diag.RulePackRegistryLoadFailed).
				Error().
				Remediation("Reinstall Stave binary or verify embedded registry integrity").
				SensitiveAttribute("error", err.Error()).
				Build(),
		}
	}
	known := reg.PackNames()
	knownSet := make(map[string]struct{}, len(known))
	for _, name := range known {
		knownSet[name] = struct{}{}
	}
	var issues []diag.Finding
	for _, raw := range cfg.EnabledControlPacks {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if _, ok := knownSet[name]; ok {
			continue
		}
		issues = append(issues, diag.NewFinding(diag.RuleUnknownControlPack).
			Error().
			Remediation("Use a configured pack name: "+strings.Join(known, ", ")).
			Attribute("pack", name).
			Build())
	}
	return issues
}
