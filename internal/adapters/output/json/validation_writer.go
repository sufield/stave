package json

import (
	"encoding/json"
	"io"

	"github.com/sufield/stave/internal/safetyenvelope"
)

// WriteValidation writes a validation report as JSON.
// When useEnvelope is true, wraps output in {"ok": ..., "data": ...}.
func WriteValidation(w io.Writer, report any, useEnvelope bool, isValid bool) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if useEnvelope {
		return enc.Encode(safetyenvelope.JSONEnvelope[any]{OK: isValid, Data: report})
	}
	return enc.Encode(report)
}
