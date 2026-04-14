package compliance

import (
	"encoding/json"
	"fmt"
	"io"
)

func renderJSON(w io.Writer, export *EvidenceExport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(export); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	return nil
}
