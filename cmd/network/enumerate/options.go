package enumerate

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
)

const (
	// DefaultPort is the default port to enumerate.
	DefaultPort = stave.DefaultSSHPort
	// DefaultFormat is the default output format for network enumeration.
	DefaultFormat = "text"
)

type options struct {
	observations string
	port         int
	format       string
}

func addFlags(cmd *cobra.Command, o *options) {
	f := cmd.Flags()
	f.StringVarP(&o.observations, "observations", "o", "", "path to observations directory (required)")
	f.IntVar(&o.port, "port", DefaultPort, fmt.Sprintf("port to enumerate (default: %d)", DefaultPort))
	f.StringVarP(&o.format, "format", "f", DefaultFormat, "output format: "+strings.Join(ValidFormats, ", "))
	_ = cmd.MarkFlagRequired("observations")
}

func (o *options) Validate() error {
	if !IsValidFormat(o.format) {
		return &ui.UserError{
			Err: fmt.Errorf("unknown format %q (valid: %s)", o.format, strings.Join(ValidFormats, ", ")),
		}
	}
	return nil
}

func (o *options) Prepare(_ *cobra.Command) error {
	o.observations = fsutil.CleanUserPath(o.observations)
	return o.Validate()
}

func (o *options) ToConfig() stave.NetworkEnumerateConfig {
	return stave.NetworkEnumerateConfig{
		SnapshotsDir: o.observations,
		Port:         o.port,
	}
}
