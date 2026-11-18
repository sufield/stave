package prove

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/network"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
)

// ValidProperties contains the safety properties supported by the network prover.
var ValidProperties = network.SupportedProperties

const (
	// DefaultProperty is the default safety property verified when none is specified.
	DefaultProperty = "bastion-ssh"
	// DefaultPort is the default port verified for network safety properties.
	DefaultPort = 22
	// DefaultFormat is the default output format for the network prover.
	DefaultFormat = "text"
)

type options struct {
	observations string
	property     string
	port         int
	format       string
}

func addFlags(cmd *cobra.Command, o *options) {
	f := cmd.Flags()
	f.StringVarP(&o.observations, "observations", "o", "", "path to observations directory (required)")
	f.StringVar(&o.property, "property", DefaultProperty, "safety property to verify: "+strings.Join(ValidProperties, ", "))
	f.IntVar(&o.port, "port", DefaultPort, fmt.Sprintf("port to verify (default: %d)", DefaultPort))
	f.StringVarP(&o.format, "format", "f", DefaultFormat, "output format: "+strings.Join(ValidFormats, ", "))
	_ = cmd.MarkFlagRequired("observations")
}

// IsValidProperty reports whether prop is one of the supported safety properties.
func IsValidProperty(prop string) bool {
	return network.IsSupportedProperty(prop)
}

func (o *options) Validate() error {
	if !IsValidProperty(o.property) {
		return &ui.UserError{
			Err: fmt.Errorf("unknown --property %q (valid: %s)", o.property, strings.Join(ValidProperties, ", ")),
		}
	}
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

func (o *options) ToConfig() stave.NetworkProveConfig {
	return stave.NetworkProveConfig{
		SnapshotsDir: o.observations,
		Property:     o.property,
		Port:         o.port,
	}
}
