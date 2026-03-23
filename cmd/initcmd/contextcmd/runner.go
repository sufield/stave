package contextcmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/internal/cli/ui"
	contexts "github.com/sufield/stave/internal/config"
	"github.com/sufield/stave/internal/pkg/jsonutil"
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
func (r *Runner) List(st *contexts.Store, format ui.OutputFormat) error {
	names := st.Names()
	active := strings.TrimSpace(st.Active)

	items := make([]ListItem, 0, len(names))
	for _, name := range names {
		c := st.Contexts[name]
		items = append(items, ListItem{
			Name:          name,
			ProjectRoot:   strings.TrimSpace(c.ProjectRoot),
			ProjectConfig: strings.TrimSpace(c.ProjectConfig),
			ControlsDir:   strings.TrimSpace(c.Defaults.ControlsDir),
			ObserveDir:    strings.TrimSpace(c.Defaults.ObservationsDir),
			Active:        name == active,
		})
	}

	if format.IsJSON() {
		return jsonutil.WriteIndented(r.Stdout, items)
	}

	if len(items) == 0 {
		_, err := fmt.Fprintln(r.Stdout, "No contexts configured.")
		return err
	}
	for _, item := range items {
		suffix := ""
		if item.Active {
			suffix = " (active)"
		}
		fmt.Fprintf(r.Stdout, "%s%s\n", item.Name, suffix)
		fmt.Fprintf(r.Stdout, "  root: %s\n", item.ProjectRoot)
		fmt.Fprintf(r.Stdout, "  config: %s\n", emptyDash(item.ProjectConfig))
		fmt.Fprintf(r.Stdout, "  controls: %s\n", emptyDash(item.ControlsDir))
		fmt.Fprintf(r.Stdout, "  observations: %s\n", emptyDash(item.ObserveDir))
	}
	return nil
}

// Create adds or updates a named context in the store.
func (r *Runner) Create(st *contexts.Store, name string, c contexts.Context) error {
	name = contexts.NormalizeName(name)
	if name == "" {
		return &ui.UserError{Err: fmt.Errorf("context name cannot be empty")}
	}

	st.Contexts[name] = c
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
	if _, ok := st.Contexts[name]; !ok {
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
func (r *Runner) Show(format ui.OutputFormat, res ShowResult) error {
	if format.IsJSON() {
		return jsonutil.WriteIndented(r.Stdout, res)
	}

	_, err := fmt.Fprintf(r.Stdout, "Context: %s (%s)\nStore: %s\nProject root: %s\nConfig: %s\nControls default: %s\nObservations default: %s\n",
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

// Delete removes a context from the store.
func (r *Runner) Delete(st *contexts.Store, name string) error {
	name = contexts.NormalizeName(name)
	if _, ok := st.Contexts[name]; !ok {
		return &ui.UserError{Err: fmt.Errorf("context %q not found", name)}
	}

	delete(st.Contexts, name)
	if strings.TrimSpace(st.Active) == name {
		st.Active = ""
	}

	if err := st.Save(); err != nil {
		return fmt.Errorf("failed to persist context deletion: %w", err)
	}

	fmt.Fprintf(r.Stdout, "Deleted context: %s\n", name)
	return nil
}
