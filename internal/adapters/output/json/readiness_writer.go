package json

import (
	"encoding/json"
	"io"

	"github.com/sufield/stave/internal/domain/validation"
)

// WriteReadinessJSON encodes a ReadinessReport as indented JSON.
func WriteReadinessJSON(w io.Writer, report validation.ReadinessReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
