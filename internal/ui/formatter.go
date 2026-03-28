package ui

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// RenderJSON writes v as indented JSON to w.
func RenderJSON(w io.Writer, v any) error {
	return jsonutil.WriteIndented(w, v)
}

// RenderText writes a single-line summary to w.
func RenderText(w io.Writer, format string, args ...any) error {
	_, err := fmt.Fprintf(w, format, args...)
	return err
}
