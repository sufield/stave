package gate

import (
	"io"
	"time"

	appconfig "github.com/sufield/stave/internal/app/config"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// config defines the parameters for enforcing a CI failure policy.
type config struct {
	Policy            appconfig.GatePolicy
	InPath            string
	BaselinePath      string
	ControlsDir       string
	ObservationsDir   string
	MaxUnsafeDuration time.Duration
	Format            appcontracts.OutputFormat
	Quiet             bool

	Clock     ports.Clock
	Sanitizer kernel.Sanitizer
	Stdout    io.Writer
	Stderr    io.Writer
}
