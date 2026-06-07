package contextcmd

import (
	"fmt"
	"io"
	"strings"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	contexts "github.com/sufield/stave/internal/config"
)

// --- Domain Models ---

// ListItem represents a single context entry for list output.
type ListItem struct {
	Name          string `json:"name"`
	ProjectRoot   string `json:"project_root"`
	ProjectConfig string `json:"project_config,omitempty"`
	ControlsDir   string `json:"controls_dir,omitempty"`
	ObserveDir    string `json:"observations_dir,omitempty"`
	Active        bool   `json:"active"`
}

// ShowResult represents the resolved active context for show output.
type ShowResult struct {
	StoreFile     string `json:"store_file"`
	SelectedBy    string `json:"selected_by"`
	Name          string `json:"name"`
	ProjectRoot   string `json:"project_root"`
	ProjectConfig string `json:"project_config,omitempty"`
	ControlsDir   string `json:"controls_dir,omitempty"`
	ObserveDir    string `json:"observations_dir,omitempty"`
}

// --- Runner ---

// Runner orchestrates the management of named project contexts.
type Runner struct {
	Stdout io.Writer
	Stderr io.Writer
}

// List retrieves all contexts from the store and renders them.
func (r *Runner) List(st *contexts.Store, format appcontracts.OutputFormat) error {
	names := st.Names()
	active := strings.TrimSpace(st.Active)

	items := make([]ListItem, 0, len(names))
	for _, name := range names {
		c, ok := st.GetContext(name)
		if !ok {
			// names came from st.Names() and the contexts map is
			// the same store; a miss here means concurrent
			// modification or store corruption. Skip the row
			// rather than silently rendering an empty one — the
			// list output otherwise looked normal but pointed at
			// nothing.
			continue
		}
		items = append(items, ListItem{
			Name:          name,
			ProjectRoot:   c.CanonicalProjectRoot(),
			ProjectConfig: c.CanonicalProjectConfig(),
			ControlsDir:   c.EffectiveControlsDir(),
			ObserveDir:    c.EffectiveObservationsDir(),
			Active:        name == active,
		})
	}

	renderer, err := NewListRenderer(format)
	if err != nil {
		return err
	}
	if err := renderer.Render(r.Stdout, items); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}

// Create adds or updates a named context in the store.
func (r *Runner) Create(st *contexts.Store, name string, c contexts.Context) error {
	name = contexts.NormalizeName(name)
	if err := contexts.ValidateName(name); err != nil {
		return &ui.UserError{Err: err}
	}

	if err := st.SetContext(name, c); err != nil {
		return &ui.UserError{Err: err}
	}
	if strings.TrimSpace(st.Active) == "" {
		st.Active = name
	}

	if err := st.Save(); err != nil {
		return fmt.Errorf("failed to save context store: %w", err)
	}

	fmt.Fprintf(r.Stdout, "Context saved: %s\n", name)
	return nil
}

// Use sets a context as the active default in the store.
func (r *Runner) Use(st *contexts.Store, name string) error {
	name = contexts.NormalizeName(name)
	if _, ok := st.GetContext(name); !ok {
		return &ui.UserError{Err: fmt.Errorf("context %q not found (available: %s)", name, strings.Join(st.Names(), ", "))}
	}

	st.Active = name
	if err := st.Save(); err != nil {
		return fmt.Errorf("failed to update active context: %w", err)
	}

	fmt.Fprintf(r.Stdout, "Active context: %s\n", name)
	return nil
}

// Show renders the currently selected context.
func (r *Runner) Show(format appcontracts.OutputFormat, res ShowResult) error {
	renderer, err := NewShowRenderer(format)
	if err != nil {
		return err
	}
	if err := renderer.Render(r.Stdout, res); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}

// Delete removes a context from the store.
func (r *Runner) Delete(st *contexts.Store, name string) error {
	name = contexts.NormalizeName(name)
	if err := st.DeleteContext(name); err != nil {
		return &ui.UserError{Err: fmt.Errorf("context %q not found", name)}
	}
	if strings.TrimSpace(st.Active) == name {
		st.Active = ""
	}

	if err := st.Save(); err != nil {
		return fmt.Errorf("failed to persist context deletion: %w", err)
	}

	fmt.Fprintf(r.Stdout, "Deleted context: %s\n", name)
	return nil
}
