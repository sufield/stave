package json

import (
	"encoding/json"
	"io"

	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/pkg/alpha/domain/validation"
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

// WriteReadinessJSON encodes a ReadinessReport as indented JSON.
func WriteReadinessJSON(w io.Writer, report validation.ReadinessReport) error {
	return jsonutil.WriteIndented(w, report)
}
