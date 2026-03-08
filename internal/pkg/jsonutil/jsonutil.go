package jsonutil

import (
	"encoding/json"
	"io"
)

// WriteIndented encodes v as indented JSON to w.
func WriteIndented(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
