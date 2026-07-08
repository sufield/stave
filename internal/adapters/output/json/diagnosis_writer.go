package json

import (
	"encoding/json"
	"fmt"
	"io"

	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
	"github.com/sufield/stave/internal/core/report"
)

// WriteDiagnosis writes a diagnosis report as bare JSON.
func WriteDiagnosis(w io.Writer, diagReport *diagnosis.Report) error {
	jsonOutput := report.NewReadiness(diagReport)
	if err := contractvalidator.ValidateReadiness(jsonOutput); err != nil {
		return fmt.Errorf("validate readiness: %w", err)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonOutput)
}
