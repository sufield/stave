package ui

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/platform/tplutil"
)

// ExecuteTemplate renders a template string against data using a
// restricted text/template engine. Delegates to tplutil.Execute.
func ExecuteTemplate(w io.Writer, tmplStr string, data any) error {
	if err := tplutil.Execute(w, tmplStr, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}
	return nil
}
