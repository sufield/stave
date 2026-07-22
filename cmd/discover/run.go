package discover

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pack"
	"github.com/sufield/stave/pkg/stave"
)

// manifest is the rendered collection manifest for the requested services.
type manifest struct {
	Services          []string          `json:"services"`
	ServicesCovered   []string          `json:"services_covered"`
	ServicesUnmatched []string          `json:"services_unmatched,omitempty"`
	Packs             []string          `json:"packs"`
	ControlCount      int               `json:"control_count"`
	Requirements      pack.Requirements `json:"requirements"`
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

	names := pack.PacksForServices(o.services, all, metas)
	packs := make([]*pack.Pack, 0, len(names))
	covered := map[string]bool{}
	controlIDs := map[string]bool{}
	for _, n := range names {
		p := all[n]
		packs = append(packs, p)
		for _, s := range pack.ServicesForPack(p, metas) {
			covered[s] = true
		}
		for _, id := range p.Resolve(metas) {
			controlIDs[id] = true
		}
	}

	merged := pack.MergeRequirements(packs)

	if o.policy {
		doc, synthErr := pack.SynthesizePolicy(merged.AWSAPICalls)
		if synthErr != nil {
			return fmt.Errorf("synthesize policy: %w", synthErr)
		}
		doc = append(doc, '\n')
		_, err = cmd.OutOrStdout().Write(doc)
		return err
	}

	// Only count a requested service as "covered" if some pack actually touches it.
	var coveredReq, unmatched []string
	for _, s := range o.services {
		if covered[s] {
			coveredReq = append(coveredReq, s)
		} else {
			unmatched = append(unmatched, s)
		}
	}

	m := manifest{
		Services:          o.services,
		ServicesCovered:   coveredReq,
		ServicesUnmatched: unmatched,
		Packs:             names,
		ControlCount:      len(controlIDs),
		Requirements:      merged,
	}

	r, err := NewRenderer(o.format)
	if err != nil {
		return &ui.UserError{Err: err}
	}
	if err := r.Render(cmd.OutOrStdout(), m); err != nil {
		return fmt.Errorf("render manifest: %w", err)
	}
	return nil
}
