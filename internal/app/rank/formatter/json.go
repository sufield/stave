package formatter

import (
	"encoding/json"
	"fmt"
	"io"

	apprank "github.com/sufield/stave/internal/app/rank"
	"github.com/sufield/stave/internal/core/report"
)

// JSON renders a Roadmap as indented JSON. The assessment parameter
// is unused — the Roadmap already carries every field a JSON consumer
// needs — but the signature matches RoadmapFormatter so callers can
// dispatch by interface.
type JSON struct{}

var _ RoadmapFormatter = (*JSON)(nil)

// Render writes rm as JSON with two-space indentation.
func (JSON) Render(w io.Writer, rm apprank.Roadmap, _ *report.Assessment) error {
	data, err := json.MarshalIndent(rm, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal roadmap: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}
