package json

import (
	"encoding/json"
	"io"
)

// WriteValidation writes a validation report as JSON.
// When useEnvelope is true, wraps output in {"ok": ..., "data": ...}.
func WriteValidation(w io.Writer, report any, useEnvelope bool, isValid bool) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if useEnvelope {
		return enc.Encode(map[string]any{"ok": isValid, "data": report})
	}
	return enc.Encode(report)
}
