package json

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/safetyenvelope"
)

// WriteVerification writes a verification result as JSON.
func WriteVerification(w io.Writer, result safetyenvelope.Verification) error {
	if err := safetyenvelope.ValidateVerification(result); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
