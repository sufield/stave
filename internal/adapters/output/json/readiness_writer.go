package json

import (
	"io"

	"github.com/sufield/stave/internal/domain/validation"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// WriteReadinessJSON encodes a ReadinessReport as indented JSON.
func WriteReadinessJSON(w io.Writer, report validation.ReadinessReport) error {
	return jsonutil.WriteIndented(w, report)
}
