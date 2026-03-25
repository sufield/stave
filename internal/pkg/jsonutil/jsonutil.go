// Package jsonutil provides JSON encoding helpers for CLI output.
package jsonutil

import (
	"encoding/json"
	"io"
)

// WriteIndented encodes v as indented, human-readable JSON to w.
// HTML escaping is disabled so characters like &, <, > render literally
// in CLI output instead of as unicode escape sequences.
func WriteIndented(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
