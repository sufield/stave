package apply

import (
	"io"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/kernel"
)

// standardIO holds resolved IO and format state for the standard apply path.
type standardIO struct {
	Stdout    io.Writer
	Stderr    io.Writer
	Stdin     io.Reader
	Sanitizer kernel.Sanitizer
	Format    appcontracts.OutputFormat
	Quiet     bool
}

// ResolveStandardIO extracts IO and format state for the standard apply path.
func ResolveStandardIO(o *ApplyOptions, cs cobraState) (standardIO, error) {
	format, err := compose.ResolveFormatValuePure(o.Format, cs.FormatChanged, false)
	if err != nil {
		return standardIO{}, err
	}
	quiet := cs.GlobalFlags.Quiet || isMachineFormat(format)
	return standardIO{
		Stdout:    compose.ResolveStdout(cs.Stdout, quiet, format),
		Stderr:    cs.Stderr,
		Stdin:     cs.Stdin,
		Sanitizer: cs.GlobalFlags.GetSanitizer(),
		Format:    format,
		Quiet:     quiet,
	}, nil
}

// isMachineFormat reports whether the output format is intended for
// machine consumption (JSON, SARIF). When true, progress messages
// and hints on stderr are suppressed to keep the output composable
// with tools like jq.
func isMachineFormat(f appcontracts.OutputFormat) bool {
	return f == appcontracts.FormatJSON || f == appcontracts.FormatSARIF
}
