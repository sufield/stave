package apply

import (
	"io"
	"log/slog"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
)

// cobraState holds all values extracted from *cobra.Command.
// Populated once in RunE; all downstream functions are cobra-free.
// Context is not stored here — it flows through function parameters.
// Flag-explicitness bits (controlsSet / formatSet / obsSet) live on
// Options instead, captured in PreRunE.
type cobraState struct {
	Logger      *slog.Logger
	Stdout      io.Writer
	Stderr      io.Writer
	Stdin       io.Reader
	GlobalFlags cliflags.GlobalFlags
}

type runMode string

const (
	runModeStandard runMode = "standard"
	runModeProfile  runMode = "profile"
)

// RunConfig holds the fully resolved execution state. Exactly one of the mode
// payloads is meaningful, determined by Mode. The standard path reads the raw
// flag strings off Options directly (parsing happens in the facade).
type RunConfig struct {
	Mode    runMode
	Profile *Config // non-nil in profile mode

	// Resolved directory paths from inference.
	ControlsDir     string
	ObservationsDir string

	// projectConfigPath is the resolved stave.yaml path (or "") passed to the
	// facade, which loads the policy itself.
	projectConfigPath string

	// UseBuiltinCatalog is set when --controls was not given and no
	// controls/ directory exists: evaluate against the embedded catalog.
	UseBuiltinCatalog bool
}

// IsProfileMode reports whether the run is in profile mode.
func (c *RunConfig) IsProfileMode() bool {
	return c != nil && c.Mode == runModeProfile
}
