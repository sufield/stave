package json

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/util/jsonutil"
)

// WriteUpcomingJSON encodes an upcoming output value as indented JSON.
func WriteUpcomingJSON(w io.Writer, v any) error {
	if err := jsonutil.WriteIndented(w, v); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}
