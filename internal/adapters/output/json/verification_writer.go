package json

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/core/report"
)

// WriteVerification writes a verification result as JSON.
func WriteVerification(w io.Writer, result *report.Attestation) error {
	if err := report.ValidateAttestation(result); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
