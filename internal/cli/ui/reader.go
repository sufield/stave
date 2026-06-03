package ui

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// ReadInput reads either stdin ("-") or a regular file path.
// When path is "-", data is read from the provided stdin reader.
func ReadInput(stdin io.Reader, path string) (data []byte, resolvedPath string, err error) {
	if path == "-" {
		data, err = fsutil.LimitedReadAll(stdin, "stdin")
		if err != nil {
			return nil, "stdin", fmt.Errorf("read stdin: %w", err)
		}
		return data, "stdin", nil
	}
	data, err = fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, path, fmt.Errorf("read file %s: %w", path, err)
	}
	return data, path, nil
}
