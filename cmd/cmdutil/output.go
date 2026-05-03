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

// WriteTo runs fn with the writer the command should target — stdout
// when path is empty, otherwise an os.Create file — and ensures the
// file Close is checked exactly once, with the body error taking
// precedence over a Close failure ("first error wins"). Replaces
// the per-command (os.Create + defer Close + manual close-error
// thread) plumbing that was duplicated across ~13 command files.
//
//	return cmdutil.WriteTo(stdout, opts.OutPath, func(w io.Writer) error {
//	    enc := json.NewEncoder(w)
//	    enc.SetIndent("", "  ")
//	    return enc.Encode(result)
//	})
//
// fn is responsible for any non-Close error; a nil Close error after
// a nil fn error returns nil. A close error after a successful body
// is propagated so a buffered-write failure cannot silently truncate.
func WriteTo(stdout io.Writer, path string, fn func(io.Writer) error) (err error) {
	if path == "" {
		return fn(stdout)
	}
	f, openErr := os.Create(path) //nolint:gosec // user-specified output path
	if openErr != nil {
		return fmt.Errorf("create output file %q: %w", path, openErr)
	}
	defer func() {
		closeErr := f.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("close output file %q: %w", path, closeErr)
		}
	}()
	return fn(f)
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
