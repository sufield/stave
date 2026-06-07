package exposure

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
)

// Input is the per-run payload assembled at the RunE boundary.
type Input struct {
	Stdin  io.Reader
	Stdout io.Writer
	File   string
}

func run(in Input) error {
	data, err := fsutil.ReadFileOrStdin(in.File, in.Stdin)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	out, err := stave.InspectExposure(data)
	if err != nil {
		return err //nolint:wrapcheck // stave.InspectExposure already wraps with context ("parse exposure input" / "encode exposure output")
	}

	if _, err := in.Stdout.Write(out); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}
