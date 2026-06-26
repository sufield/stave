package pack

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pack"
	"github.com/sufield/stave/pkg/stave"
)

// catalogMeta loads the active catalog as pack.ControlMeta for resolution.
func catalogMeta(o *options) ([]pack.ControlMeta, error) {
	sums, err := stave.CatalogControlSummaries(o.controls, !o.controlsSet)
	if err != nil {
		return nil, fmt.Errorf("load control catalog: %w", err)
	}
	metas := make([]pack.ControlMeta, len(sums))
	for i, s := range sums {
		metas[i] = pack.ControlMeta{ID: s.ID, Severity: s.Severity}
	}
	return metas, nil
}

// listLine is one row of `pack list`.
type listLine struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	Count int    `json:"control_count"`
}

func runList(cmd *cobra.Command, o *options) error {
	all, err := pack.LoadAll()
	if err != nil {
		return fmt.Errorf("load packs: %w", err)
	}
	metas, err := catalogMeta(o)
	if err != nil {
		return err
	}
	lines := make([]listLine, 0, len(all))
	for _, name := range pack.Names(all) {
		p := all[name]
		lines = append(lines, listLine{Name: p.Name, Title: p.Title, Count: len(p.Resolve(metas))})
	}
	r, err := NewRenderer(o.format)
	if err != nil {
		return &ui.UserError{Err: err}
	}
	if err := r.Render(cmd.OutOrStdout(), lines); err != nil {
		return fmt.Errorf("render pack list: %w", err)
	}
	return nil
}

// showPayload is the resolved view of one pack for `pack show`.
type showPayload struct {
	Pack    *pack.Pack `json:"pack"`
	Count   int        `json:"control_count"`
	Missing []string   `json:"missing_ids,omitempty"`
}

func runShow(cmd *cobra.Command, o *options, name string) error {
	p, err := pack.Load(name)
	if err != nil {
		return &ui.UserError{Err: err} // unknown pack → exit 2
	}
	metas, err := catalogMeta(o)
	if err != nil {
		return err
	}
	payload := showPayload{Pack: p, Count: len(p.Resolve(metas)), Missing: p.Missing(metas)}
	r, err := NewRenderer(o.format)
	if err != nil {
		return &ui.UserError{Err: err}
	}
	if err := r.Render(cmd.OutOrStdout(), payload); err != nil {
		return fmt.Errorf("render pack: %w", err)
	}
	return nil
}
