package json

import (
	"encoding/json"
	"io"
)

// WriteValidation writes a validation report as bare JSON.
func WriteValidation(w io.Writer, report any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
