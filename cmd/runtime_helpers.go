package cmd

import (
	"os"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/configservice"
	"github.com/sufield/stave/internal/platform/logging"
)

// expandAliasIfMatch checks if os.Args[1] matches a user-defined alias.
// If so, it replaces the command arguments with the expanded alias tokens
// followed by any extra arguments the user passed.
func expandAliasIfMatch() {
	if len(os.Args) < 2 || strings.HasPrefix(os.Args[1], "-") {
		return
	}
	aliases := cmdutil.LoadUserAliases()
	if len(aliases) == 0 {
		return
	}
	expanded, ok := aliases[os.Args[1]]
	if !ok {
		return
	}
	tokens := strings.Fields(expanded)
	newArgs := append(tokens, os.Args[2:]...)
	RootCmd.SetArgs(newArgs)
}

func attachRunIDFromPlan(plan *appeval.EvaluationPlan) {
	if plan == nil {
		return
	}
	attachRunID(plan.ObservationsHash.String(), plan.ControlsHash.String())
}

func attachRunID(inputsHash, controlsHash string) {
	logging.SetDefaultLogger(globalLogger)
	cmdutil.AttachRunID(inputsHash, controlsHash)
	globalLogger = logging.DefaultLogger()
}

func configKeyCompletions() []string {
	baseKeys := cmdutil.ConfigKeyService.TopLevelKeys()
	tiers := []string{cmdutil.DefaultRetentionTier}

	if cfg, ok := cmdutil.FindProjectConfig(); ok {
		if t := cmdutil.NormalizeRetentionTier(cfg.RetentionTier); t != "" {
			tiers = append(tiers, t)
		}
		for tier := range cfg.RetentionTiers {
			t := cmdutil.NormalizeRetentionTier(tier)
			if t != "" {
				tiers = append(tiers, t)
			}
		}
	}

	return configservice.BuildKeyCompletions(baseKeys, tiers)
}
