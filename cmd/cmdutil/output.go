package cmdutil

import (
	"fmt"
	"io"
	"os"
)

// OutputOptions captures the canonical "--output PATH" flag pattern.
// Existing commands use a mix of field names (Out, OutputFile, OutPath,
// OutFile, OutputPath); new commands should embed or use this struct so
// the convention is consistent.
type OutputOptions struct {
	Path string
}

// Open returns the writer the command should send output to and a
// closer to defer. When Path is empty, output goes to stdout and the
// closer is a no-op.
//
// The closer takes a *error so it can propagate the file-close error
// back through the named return value of the calling function:
//
//	func runCmd() (err error) {
//	    out, closer, openErr := opts.Output.Open(stdout)
//	    if openErr != nil { return openErr }
//	    defer closer(&err)
//	    // ... write to out ...
//	}
//
// This preserves the "first error wins" semantics: a runtime error from
// the body returns first; if the body succeeds but Close fails, that
// error is returned instead.
func (o *OutputOptions) Open(stdout io.Writer) (io.Writer, func(*error), error) {
	if o == nil || o.Path == "" {
		return stdout, func(*error) {}, nil
	}
	f, err := os.Create(o.Path) //nolint:gosec // user-specified output path
	if err != nil {
		return nil, nil, fmt.Errorf("create output file %q: %w", o.Path, err)
	}
	return f, func(e *error) {
		closeErr := f.Close()
		if *e == nil && closeErr != nil {
			*e = fmt.Errorf("close output file %q: %w", o.Path, closeErr)
		}
	}, nil
}
