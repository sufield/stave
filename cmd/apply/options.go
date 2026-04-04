package apply

import (
	"io"
	"log/slog"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	appconfig "github.com/sufield/stave/internal/app/config"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/core/ports"
)

// cobraState holds all values extracted from *cobra.Command.
// Populated once in RunE; all downstream functions are cobra-free.
// Context is not stored here — it flows through function parameters.
type cobraState struct {
	Logger        *slog.Logger
	Stdout        io.Writer
	Stderr        io.Writer
	Stdin         io.Reader
	GlobalFlags   cliflags.GlobalFlags
	FormatChanged bool
	ObsChanged    bool
}

type runMode string

const (
	runModeStandard runMode = "standard"
	runModeProfile  runMode = "profile"
)

// RunConfig holds the fully resolved execution state.
// Exactly one of Params or Profile is meaningful, determined by Mode.
// All resolved values live here — no downstream code reads back from Options.
type RunConfig struct {
	Mode         runMode
	Params       *applyParams // non-nil in standard mode
	Profile      *Config      // non-nil in profile mode
	profileClock ports.Clock  // used by profile mode

	// Resolved directory paths from inference. Used by buildEvaluatorInput
	// instead of reading back from the mutable Options receiver.
	ControlsDir     string
	ObservationsDir string

	// Pre-loaded project config, resolved once during Resolve().
	// Shared by buildEvaluatorInput and Build to avoid repeated disk reads.
	projectConfig     *appconfig.ProjectConfig
	projectConfigPath string
}

// applyParams holds validated and parsed domain types.
type applyParams struct {
	maxUnsafeDuration time.Duration
	clock             ports.Clock
	source            appeval.ObservationSource
}

func buildClock(now time.Time) ports.Clock {
	if !now.IsZero() {
		return ports.FixedClock(now)
	}
	return ports.RealClock{}
}
