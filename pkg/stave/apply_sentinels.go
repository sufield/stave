package stave

import (
	appeval "github.com/sufield/stave/internal/app/eval"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
)

// Apply evaluation sentinels, re-exported so callers (the apply command, other
// pkg/stave consumers) can map evaluation failures to remediation hints with
// errors.Is without importing internal/app/eval or internal/contracts/validator.
//
// These are the SAME error values the internal packages define — aliasing, not
// wrapping — so errors.Is(err, stave.ErrNoControls) is identical to matching
// the internal sentinel. EvaluateStandard / EvaluateProfile propagate them
// through the %w chain unchanged.
var (
	// ErrNoControls marks an evaluation that found no control definitions.
	ErrNoControls = appeval.ErrNoControls
	// ErrNoSnapshots marks an evaluation that found no observation snapshots.
	ErrNoSnapshots = appeval.ErrNoSnapshots
	// ErrSchemaValidation marks an observation that failed schema validation.
	ErrSchemaValidation = contractvalidator.ErrSchemaValidationFailed
)
