package cmd

import (
	"log/slog"
	"math"

	"github.com/sufield/stave/internal/adapters/pruner"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// MaxConfigurable* upper-bound the values an operator can set via
// stave.yaml. Beyond these caps the underlying subsystems either
// allocate dangerously large buffers (snapshot enumeration at 10M
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
	// MaxConfigurableConfidenceMultiplier bounds the HIGH/MEDIUM
	// confidence multipliers at 1000x. Defaults are 4x (HIGH) and
	// 2x (MEDIUM); anything above 1000 is almost certainly a typo
	// (e.g., a misplaced decimal) that would cause downstream
	// classification thresholds to overflow into nonsense values.
	MaxConfigurableConfidenceMultiplier = 1000
	// MaxConfigurableInputFileBytes bounds the largest single input
	// file Stave will read at 4 GiB. The default is 256 MB. Beyond
	// this cap a single observation file would exhaust process
	// memory before parsing — and on 32-bit hosts would overflow
	// int conversions in fsutil. Operators staging genuinely large
	// inputs should split them rather than raise this limit.
	//
	// 32-BIT NOTE: this constant is `int` and on 32-bit platforms
	// `int` is 32 bits, so 4 GiB literally cannot be expressed —
	// the package-level cap is clamped at runtime by
	// effectiveMaxConfigurableInputFileBytes() to math.MaxInt32-1.
	// All readers should call that helper rather than referencing
	// the constant directly when sizing platform-bounded buffers.
	MaxConfigurableInputFileBytes = 4 * 1024 * 1024 * 1024
)

// effectiveMaxConfigurableInputFileBytes returns the configured
// input-file cap clamped to the host's int range. On 64-bit hosts
// it returns MaxConfigurableInputFileBytes unchanged (4 GiB fits
// trivially). On 32-bit hosts it clamps at math.MaxInt32 - 1 so the
// constant cannot overflow downstream `int` math in fsutil.
func effectiveMaxConfigurableInputFileBytes() int64 {
	const cap32 = int64(math.MaxInt32 - 1)
	if MaxConfigurableInputFileBytes > cap32 {
		// 32-bit host: the literal already wraps, so guard against
		// a wrapped (negative) value in addition to clamping the
		// successful path.
		return cap32
	}
	return int64(MaxConfigurableInputFileBytes)
}

// resolveConfigurableLimits applies user-configurable runtime limits
// from stave.yaml. Invalid values are warned about (so the operator
// knows their config did not take effect) and then ignored — the
// conservative defaults stay in place rather than failing the entire
// startup over a typo'd byte-size.
func (a *App) resolveConfigurableLimits(eval *appconfig.GovernanceResolver) {
	// Bootstrap can hand a nil resolver when project-config loading
	// failed and the command is annotated as config-optional. Calling
	// eval.MaxInputFileSize() / ConfidenceHighMultiplier() etc. on a
	// nil resolver panics; the right behaviour is to leave the
	// runtime's defaults in place. Mirrors the same nil guard in
	// resolveGlobalFlagDefaults (bootstrap.go:118).
	if eval == nil {
		return
	}

	logger := a.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Max input file size (default 256 MB). Cap reads via
	// effectiveMaxConfigurableInputFileBytes so a 32-bit host clamps
	// below math.MaxInt32 — the package constant is 4 GiB which
	// exceeds the int range on those platforms.
	maxBytes := effectiveMaxConfigurableInputFileBytes()
	if raw := eval.MaxInputFileSize(); raw != "" {
		if n, err := kernel.ParseByteSize(raw); err == nil {
			if n > maxBytes {
				logger.Warn("config: clamping max_input_file_size to configured maximum",
					"requested", n, "max", maxBytes)
				n = maxBytes
			}
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
	//
	// Only seed defaults when the field is its zero value. App is not
	// designed for reuse across bootstrap calls, but a test harness
	// that pre-populates a.Confidence with custom multipliers should
	// not have its values silently clobbered here.
	if a.Confidence == (evaluation.ConfidenceCalculator{}) {
		a.Confidence = evaluation.DefaultConfidenceCalculator()
	}
	if h, m := eval.ConfidenceHighMultiplier(), eval.ConfidenceMedMultiplier(); h > 0 || m > 0 {
		if h > 0 {
			if h > MaxConfigurableConfidenceMultiplier {
				logger.Warn("config: clamping confidence_high_multiplier to configured maximum",
					"requested", h, "max", MaxConfigurableConfidenceMultiplier)
				h = MaxConfigurableConfidenceMultiplier
			}
			a.Confidence.HighMultiplier = h
		}
		if m > 0 {
			if m > MaxConfigurableConfidenceMultiplier {
				logger.Warn("config: clamping confidence_med_multiplier to configured maximum",
					"requested", m, "max", MaxConfigurableConfidenceMultiplier)
				m = MaxConfigurableConfidenceMultiplier
			}
			a.Confidence.MedMultiplier = m
		}
	}

	// Max snapshot files for directory enumeration (default 100,000)
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
