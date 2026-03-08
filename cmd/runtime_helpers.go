package cmd

import (
	"os"
	"sort"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil"
	appeval "github.com/sufield/stave/internal/app/eval"
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
	keys := make([]string, 0, len(baseKeys)+16)
	keys = append(keys, baseKeys...)

	tierSet := map[string]struct{}{}
	tierSet[cmdutil.DefaultRetentionTier] = struct{}{}

	if cfg, ok := cmdutil.FindProjectConfig(); ok {
		if t := cmdutil.NormalizeRetentionTier(cfg.RetentionTier); t != "" {
			tierSet[t] = struct{}{}
		}
		for tier := range cfg.RetentionTiers {
			t := cmdutil.NormalizeRetentionTier(tier)
			if t != "" {
				tierSet[t] = struct{}{}
			}
		}
	}

	tiers := make([]string, 0, len(tierSet))
	for tier := range tierSet {
		tiers = append(tiers, tier)
	}
	sort.Strings(tiers)
	for _, tier := range tiers {
		keys = append(keys, "snapshot_retention_tiers."+tier)
		keys = append(keys, "snapshot_retention_tiers."+tier+".older_than")
		keys = append(keys, "snapshot_retention_tiers."+tier+".keep_min")
	}

	sort.Strings(keys)
	return keys
}
