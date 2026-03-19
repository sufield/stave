//go:build stavedev

package artifacts

import (
	"io"

	"github.com/sufield/stave/internal/app/artifacts"
	"github.com/sufield/stave/internal/app/catalog"
)

func formatOutput(w io.Writer, cfg catalog.ListConfig, rows []catalog.ControlRow) error {
	return artifacts.FormatControlOutput(w, cfg, rows)
}
