package formatter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/app/sprintplanner"
)

// JSONSprint renders a sprint planning result as indented JSON.
// The text counterpart is TextSprint; together they cover the two
// formats `stave rank --sprint` advertises.
type JSONSprint struct{}

var _ SprintFormatter = (*JSONSprint)(nil)

// Render writes r as JSON with two-space indentation.
func (JSONSprint) Render(w io.Writer, r sprintplanner.SprintResult) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sprint result: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}
