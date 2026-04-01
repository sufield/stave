package cmd

import (
	"github.com/sufield/stave/internal/adapters/pruner"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// resolveConfigurableLimits applies user-configurable runtime limits from
// stave.yaml. Invalid values are silently ignored (keeps conservative defaults).
func (a *App) resolveConfigurableLimits(eval *appconfig.Evaluator) {
	// Max input file size (default 256 MB)
	if raw := eval.MaxInputFileSize(); raw != "" {
		if n, err := kernel.ParseByteSize(raw); err == nil {
			fsutil.SetMaxInputFileBytes(n)
		}
	}

	// Max gap threshold (default 12h) — flows through Runner.MaxGapThreshold
	// which callers set from config. The exported DefaultMaxGapThreshold
	// constant in engine/ is the fallback.

	// Confidence classification multipliers (default HIGH=4x, MEDIUM=2x)
	if h, m := eval.ConfidenceHighMultiplier(), eval.ConfidenceMedMultiplier(); h > 0 || m > 0 {
		high := h
		med := m
		if high == 0 {
			high = evaluation.DefaultConfidenceHighMultiplier
		}
		if med == 0 {
			med = evaluation.DefaultConfidenceMedMultiplier
		}
		evaluation.SetConfidenceThresholds(high, med)
	}

	// Max snapshot files for directory scanning (default 100,000)
	if n := eval.MaxSnapshotFiles(); n > 0 {
		pruner.SetDefaultMaxFiles(n)
	}

	// Production guard blocked commands
	if cmds := eval.BlockedCommands(); len(cmds) > 0 {
		SetBlockedCommands(cmds)
	}

	// Max validation errors reported (default 3)
	if n := eval.MaxValidationErrors(); n > 0 {
		safetyenvelope.SetMaxValidationErrors(n)
	}
}
