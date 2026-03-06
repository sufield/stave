package ui

import (
	"io"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// ReadInput reads either stdin ("-") or a regular file path.
// When path is "-", data is read from the provided stdin reader.
func ReadInput(stdin io.Reader, path string) ([]byte, string, error) {
	if path == "-" {
		data, err := fsutil.LimitedReadAll(stdin, "stdin")
		return data, "stdin", err
	}
	data, err := fsutil.ReadFileLimited(path)
	return data, path, err
}
