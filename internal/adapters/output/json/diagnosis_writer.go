package json

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
	"github.com/sufield/stave/internal/core/report"
)

// WriteDiagnosis writes a diagnosis report as bare JSON.
func WriteDiagnosis(w io.Writer, diagReport *diagnosis.Report) error {
	jsonOutput := report.NewReadiness(diagReport)
	if err := report.ValidateReadiness(jsonOutput); err != nil {
		return fmt.Errorf("validate readiness: %w", err)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonOutput)
}
