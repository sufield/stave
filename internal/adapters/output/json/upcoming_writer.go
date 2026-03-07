package json

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteUpcomingJSON encodes an upcoming output value as indented JSON.
func WriteUpcomingJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}
