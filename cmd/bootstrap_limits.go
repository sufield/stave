package cmd

import (
	"log/slog"
	"math"

	appconfig "github.com/sufield/stave/internal/app/config"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
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
	// 32-BIT NOTE: this is an UNTYPED integer constant — Go gives
	// it arbitrary compile-time precision so 4 GiB is representable
	// at the package level on any platform. The overflow risk is
	// downstream: when the value is forced into an `int` (the
	// width of which is 32 bits on 32-bit hosts), the conversion
	// truncates. effectiveMaxConfigurableInputFileBytes() performs
	// the platform-aware clamp (to math.MaxInt32 - 1 on 32-bit
	// hosts, otherwise unchanged). All readers should call that
	// helper rather than referencing the constant directly when
	// sizing platform-bounded buffers.
	MaxConfigurableInputFileBytes = 4 * 1024 * 1024 * 1024
)

// effectiveMaxConfigurableInputFileBytes returns the configured
// input-file cap clamped to the host's int range. On 64-bit hosts
// it returns MaxConfigurableInputFileBytes unchanged (4 GiB fits
// trivially). On 32-bit hosts it clamps at math.MaxInt32 - 1 so the
// constant cannot overflow downstream `int` math in fsutil.
//
// The clamp uses math.MaxInt (platform-sized) rather than
// math.MaxInt32: on 64-bit hosts MaxInt is 2^63-1 so 4 GiB sits well
// below the cap and passes through unchanged; on 32-bit hosts MaxInt
// equals MaxInt32, so the comparison still triggers and we fall back
// to the 32-bit-safe ceiling.
func effectiveMaxConfigurableInputFileBytes() int64 {
	if MaxConfigurableInputFileBytes > int64(math.MaxInt) {
		// 32-bit host: the package-level int literal cannot represent
		// 4 GiB, so clamp to the largest int we can safely round-trip
		// through downstream `int` math.
		return int64(math.MaxInt32 - 1)
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
	// Stored on App and passed to Assessor during wiring, not as
	// global state.
	//
	// Use the explicit confidenceInitialized flag rather than a
	// zero-value comparison: a test harness pre-populating
	// a.Confidence with all-zero multipliers (a legitimate but rare
	// "no confidence weighting" mode) would otherwise have its
	// values silently overwritten by the default. Tests that want
	// the default seeding behaviour leave the flag false; tests
	// that pre-populate Confidence should set the flag true so
	// their values stick.
	if !a.confidenceInitialized {
		a.Confidence = evaluation.DefaultConfidenceCalculator()
		a.confidenceInitialized = true
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

	// Max validation errors reported (default 3)
	if n := eval.MaxValidationErrors(); n > 0 {
		if n > MaxConfigurableValidationErrors {
			logger.Warn("config: clamping max_validation_errors to configured maximum",
				"requested", n, "max", MaxConfigurableValidationErrors)
			n = MaxConfigurableValidationErrors
		}
		contractvalidator.SetMaxValidationErrors(n)
	}
}
