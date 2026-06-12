package apply

import (
	"fmt"
	"io"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
)

// StandardIO holds resolved IO and format state for the standard apply path.
type StandardIO struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
	Format cmdutil.OutputFormat
	Quiet  bool
}

// ResolveStandardIO extracts IO and format state for the standard apply path.
func ResolveStandardIO(o *Options, cs cobraState) (StandardIO, error) {
	format, err := compose.ResolveFormatValue(string(o.Format))
	if err != nil {
		return StandardIO{}, fmt.Errorf("resolve output format: %w", err)
	}
	quiet := cs.GlobalFlags.Quiet || isMachineFormat(format)
	return StandardIO{
		Stdout: compose.ResolveStdout(cs.Stdout, quiet, format),
		Stderr: cs.Stderr,
		Stdin:  cs.Stdin,
		Format: format,
		Quiet:  quiet,
	}, nil
}

// isMachineFormat reports whether the output format is intended for machine
// consumption (JSON, SARIF). When true, progress messages and hints on stderr
// are suppressed to keep the output composable with tools like jq.
func isMachineFormat(f cmdutil.OutputFormat) bool {
	return f == cmdutil.FormatJSON || f == cmdutil.FormatSARIF
}
