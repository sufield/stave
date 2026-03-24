package json

import (
	"encoding/json"
	"io"

	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// WriteValidation writes a validation report as bare JSON.
func WriteValidation(w io.Writer, report any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// WriteReadinessJSON encodes a readiness report as indented JSON.
// Accepts any type so callers can pass enriched wrappers.
func WriteReadinessJSON(w io.Writer, report any) error {
	return jsonutil.WriteIndented(w, report)
}
