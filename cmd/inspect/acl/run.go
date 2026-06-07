package acl

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
)

// Input is the per-run payload assembled at the RunE boundary. No
// cobra reference — RunE resolves Stdin/Stdout before calling run,
// so this package can stay off the cobra import graph.
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

	out, err := stave.InspectACL(data)
	if err != nil {
		return err //nolint:wrapcheck // stave.InspectACL already wraps with context ("parse ACL grants" / "encode ACL report")
	}

	if _, err := in.Stdout.Write(out); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}
