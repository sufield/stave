package contextcmd

import (
	"fmt"
	"io"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// --- List renderers ---

// ListRenderer is the polymorphic format-dispatch interface for
// `stave config context list`. Concrete implementations delegate to
// jsonutil.WriteIndented / the package's text-writing helper so the
// rendered bytes are byte-identical to the pre-Renderer-pattern output.
type ListRenderer interface {
	Render(w io.Writer, items []ListItem) error
}

// ListJSONRenderer emits the context list as indented JSON.
type ListJSONRenderer struct{}

// Render implements ListRenderer.
func (ListJSONRenderer) Render(w io.Writer, items []ListItem) error {
	if err := jsonutil.WriteIndented(w, items); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// ListTextRenderer writes the human-readable context list.
type ListTextRenderer struct{}

// Render implements ListRenderer.
func (ListTextRenderer) Render(w io.Writer, items []ListItem) error {
	if len(items) == 0 {
		_, err := fmt.Fprintln(w, "No contexts configured.")
		return err
	}
	for _, item := range items {
		suffix := ""
		if item.Active {
			suffix = " (active)"
		}
		fmt.Fprintf(w, "%s%s\n", item.Name, suffix)
		fmt.Fprintf(w, "  root: %s\n", item.ProjectRoot)
		fmt.Fprintf(w, "  config: %s\n", emptyDash(item.ProjectConfig))
		fmt.Fprintf(w, "  controls: %s\n", emptyDash(item.ControlsDir))
		fmt.Fprintf(w, "  observations: %s\n", emptyDash(item.ObserveDir))
	}
	return nil
}

// NewListRenderer maps a typed OutputFormat to its concrete
// ListRenderer. The format enum is validated upstream at flag-parse
// time, so an unknown value here is defensive — it returns an explicit
// error rather than silently falling back.
func NewListRenderer(format appcontracts.OutputFormat) (ListRenderer, error) {
	switch format {
	case appcontracts.FormatJSON:
		return ListJSONRenderer{}, nil
	case appcontracts.FormatText:
		return ListTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}

// --- Show renderers ---

// ShowRenderer is the polymorphic format-dispatch interface for
// `stave config context show`. Concrete implementations delegate to
// jsonutil.WriteIndented / fmt so the rendered bytes are byte-identical
// to the pre-Renderer-pattern output.
type ShowRenderer interface {
	Render(w io.Writer, res ShowResult) error
}

// ShowJSONRenderer emits the resolved context as indented JSON.
type ShowJSONRenderer struct{}

// Render implements ShowRenderer.
func (ShowJSONRenderer) Render(w io.Writer, res ShowResult) error {
	if err := jsonutil.WriteIndented(w, res); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// ShowTextRenderer writes the human-readable resolved context.
type ShowTextRenderer struct{}

// Render implements ShowRenderer.
func (ShowTextRenderer) Render(w io.Writer, res ShowResult) error {
	_, err := fmt.Fprintf(w, "Context: %s (%s)\nStore: %s\nProject root: %s\nConfig: %s\nControls default: %s\nObservations default: %s\n",
		res.Name,
		res.SelectedBy,
		res.StoreFile,
		res.ProjectRoot,
		emptyDash(res.ProjectConfig),
		emptyDash(res.ControlsDir),
		emptyDash(res.ObserveDir),
	)
	return err
}

// NewShowRenderer maps a typed OutputFormat to its concrete
// ShowRenderer. The format enum is validated upstream at flag-parse
// time, so an unknown value here is defensive — it returns an explicit
// error rather than silently falling back.
func NewShowRenderer(format appcontracts.OutputFormat) (ShowRenderer, error) {
	switch format {
	case appcontracts.FormatJSON:
		return ShowJSONRenderer{}, nil
	case appcontracts.FormatText:
		return ShowTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: text | json)", format)
}
