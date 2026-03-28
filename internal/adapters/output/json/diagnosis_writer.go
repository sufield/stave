package json

import (
	"encoding/json"
	"io"

	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// WriteDiagnosis writes a diagnosis report as bare JSON.
func WriteDiagnosis(w io.Writer, report *diagnosis.Report) error {
	jsonOutput := safetyenvelope.NewDiagnose(report)
	if err := safetyenvelope.ValidateDiagnose(jsonOutput); err != nil {
		return err
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonOutput)
}
