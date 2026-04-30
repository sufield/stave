package cmd

import (
	"log/slog"

	"github.com/sufield/stave/internal/adapters/pruner"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// MaxConfigurable* upper-bound the values an operator can set via
// stave.yaml. Beyond these caps the underlying subsystems either
// allocate dangerously large buffers (snapshot scanning at 10M
// files) or amplify a single bad input file into millions of
// validation-error rows that no consumer can render. Capping is
// done in the bootstrap path with a warning so operators see what
// they asked for and what they got.
const (
	// MaxConfigurableSnapshotFiles bounds pruner.SetDefaultMaxFiles
	// at 1M — a flat directory of 1M JSON files is already absurd
	// for any realistic snapshot workload, and the upstream Walk
	// allocates a metadata struct per file.
	MaxConfigurableSnapshotFiles = 1_000_000
	// MaxConfigurableValidationErrors bounds the per-document
	// validation-error count at 10K. Above that, downstream
	// reporters (text, JSON, SARIF) all become unreadable; SARIF
	// in particular OOMs on a single document with millions of
	// findings.
	MaxConfigurableValidationErrors = 10_000
)

// resolveConfigurableLimits applies user-configurable runtime limits
// from stave.yaml. Invalid values are warned about (so the operator
// knows their config did not take effect) and then ignored — the
// conservative defaults stay in place rather than failing the entire
// startup over a typo'd byte-size.
func (a *App) resolveConfigurableLimits(eval *appconfig.GovernanceResolver) {
	logger := a.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Max input file size (default 256 MB)
	if raw := eval.MaxInputFileSize(); raw != "" {
		if n, err := kernel.ParseByteSize(raw); err == nil {
			fsutil.SetMaxInputFileBytes(n)
		} else {
			logger.Warn("config: ignoring invalid max_input_file_size",
				"value", raw, "error", err)
		}
	}

	// Max gap threshold (default 12h) — flows through Assessor.ContinuityLimit
	// which callers set from config. The exported DefaultContinuityLimit
	// constant in engine/ is the fallback.

	// Confidence classification multipliers (default HIGH=4x, MEDIUM=2x).
	// Stored on App and passed to Assessor during wiring, not as global state.
	a.Confidence = evaluation.DefaultConfidenceCalculator()
	if h, m := eval.ConfidenceHighMultiplier(), eval.ConfidenceMedMultiplier(); h > 0 || m > 0 {
		if h > 0 {
			a.Confidence.HighMultiplier = h
		}
		if m > 0 {
			a.Confidence.MedMultiplier = m
		}
	}

	// Max snapshot files for directory scanning (default 100,000)
	if n := eval.MaxSnapshotFiles(); n > 0 {
		if n > MaxConfigurableSnapshotFiles {
			logger.Warn("config: clamping max_snapshot_files to configured maximum",
				"requested", n, "max", MaxConfigurableSnapshotFiles)
			n = MaxConfigurableSnapshotFiles
		}
		pruner.SetDefaultMaxFiles(n)
	}

	// Production guard blocked commands
	if cmds := eval.BlockedCommands(); len(cmds) > 0 {
		SetBlockedCommands(cmds)
	}

	// Max validation errors reported (default 3)
	if n := eval.MaxValidationErrors(); n > 0 {
		if n > MaxConfigurableValidationErrors {
			logger.Warn("config: clamping max_validation_errors to configured maximum",
				"requested", n, "max", MaxConfigurableValidationErrors)
			n = MaxConfigurableValidationErrors
		}
		report.SetMaxValidationErrors(n)
	}
}
