package trend

import (
	"encoding/json"
	"fmt"
	"io"
)

func renderTrendJSON(w io.Writer, r *trendReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	return nil
}
