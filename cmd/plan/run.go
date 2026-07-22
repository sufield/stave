package plan

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave/pack"
	"github.com/sufield/stave/pkg/stave"
)

// row is one service's preview line.
type row struct {
	Service string `json:"service"`
	pack.SeverityCounts
}

// preview is the rendered plan.
type preview struct {
	Services []string            `json:"services,omitempty"`
	Pack     string              `json:"pack,omitempty"`
	Rows     []row               `json:"rows"`
	Total    pack.SeverityCounts `json:"total"`
	// CollectionOrder lists services severity-weighted (most critical first).
	CollectionOrder []string `json:"collection_order"`
}

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

func run(cmd *cobra.Command, o *options) error {
	metas, err := catalogMeta(o)
	if err != nil {
		return err
	}
	all, err := pack.LoadAll()
	if err != nil {
		return fmt.Errorf("load packs: %w", err)
	}

	var controlIDs []string
	var services []string
	seen := map[string]bool{}
	add := func(ids []string) {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				controlIDs = append(controlIDs, id)
			}
		}
	}

	if o.pack != "" {
		p, perr := pack.Load(o.pack)
		if perr != nil {
			return &ui.UserError{Err: perr} // unknown pack -> exit 2
		}
		add(p.Resolve(metas))
		services = pack.ServicesForPack(p, metas)
	} else {
		for _, n := range pack.PacksForServices(o.services, all, metas) {
			add(all[n].Resolve(metas))
		}
		services = o.services
	}

	counts := pack.CountByService(controlIDs, metas, services)
	var rows []row
	var total pack.SeverityCounts
	for svc, c := range counts {
		rows = append(rows, row{Service: svc, SeverityCounts: c})
		total.Critical += c.Critical
		total.High += c.High
		total.Medium += c.Medium
		total.Low += c.Low
		total.Info += c.Info
		total.Total += c.Total
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Service < rows[j].Service })

	order := make([]row, len(rows))
	copy(order, rows)
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].Critical != order[j].Critical {
			return order[i].Critical > order[j].Critical
		}
		return order[i].High > order[j].High
	})
	collectionOrder := make([]string, len(order))
	for i, r := range order {
		collectionOrder[i] = r.Service
	}

	p := preview{Pack: o.pack, Rows: rows, Total: total, CollectionOrder: collectionOrder}
	if o.pack == "" {
		p.Services = o.services
	}

	r, err := NewRenderer(o.format)
	if err != nil {
		return &ui.UserError{Err: err}
	}
	if err := r.Render(cmd.OutOrStdout(), p); err != nil {
		return fmt.Errorf("render plan: %w", err)
	}
	return nil
}
