package projconfig

import (
	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/pkg/stave"
)

// PackConfigIssues checks for unknown control pack names in the project
// config. Project-config discovery (locating and reading stave.yaml) is a
// command-layer concern and stays here; the pack-name check against the
// embedded registry lives in pkg/stave (stave.ValidatePackConfiguration).
//
// Shared by `stave validate` and `stave apply --dry-run` so neither command
// depends on the other.
func PackConfigIssues() []diag.Finding {
	cfg, ok, cfgErr := FindProjectConfig()
	if cfgErr != nil {
		return []diag.Finding{
			diag.NewFinding(diag.RuleProjectConfigLoadFailed).
				Error().
				Remediation("Check stave.yaml for syntax errors").
				SensitiveAttribute("error", cfgErr.Error()).
				Build(),
		}
	}
	if !ok {
		return nil
	}
	return stave.ValidatePackConfiguration(cfg.EnabledControlPacks)
}
