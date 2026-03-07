package json

import (
	"encoding/json"
	"io"

	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// WriteDiagnosis writes a diagnosis report as JSON.
// When useEnvelope is true, wraps output in {"ok": ..., "data": ...}.
func WriteDiagnosis(w io.Writer, report *diagnosis.Report, useEnvelope bool) error {
	jsonOutput := safetyenvelope.NewDiagnose(report)
	if err := safetyenvelope.ValidateDiagnose(jsonOutput); err != nil {
		return err
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if useEnvelope {
		envelope := safetyenvelope.JSONEnvelope[safetyenvelope.Diagnose]{
			OK:   len(jsonOutput.Report.Entries) == 0,
			Data: jsonOutput,
		}
		return enc.Encode(envelope)
	}
	return enc.Encode(jsonOutput)
}
