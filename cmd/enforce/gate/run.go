package gate

import (
	"io"
	"time"

	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// config defines the parameters for enforcing a CI failure policy.
type config struct {
	Policy            appconfig.GatePolicy
	InPath            string
	BaselinePath      string
	ControlsDir       string
	ObservationsDir   string
	MaxUnsafeDuration time.Duration
	Format            ui.OutputFormat
	Quiet             bool

	Clock     ports.Clock
	Sanitizer kernel.Sanitizer
	Stdout    io.Writer
	Stderr    io.Writer
}
