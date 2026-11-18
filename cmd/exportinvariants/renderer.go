package exportinvariants

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/pkg/stave"
)

func validateFormat(format string) error {
	trimmed := strings.TrimSpace(format)
	if trimmed == "" || strings.EqualFold(trimmed, "json") {
		return nil
	}
	return fmt.Errorf("--format must be json (got %q): %w", format, stave.ErrInvalidInput)
}

func renderJSON(w io.Writer, out *stave.InvariantExport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encode controls: %w", err)
	}
	return nil
}
