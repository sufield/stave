package stave

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/adapters/controls/builtin"
	predicates "github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/controldata"
	"github.com/sufield/stave/pkg/stave/internal/applycore"
	"github.com/sufield/stave/pkg/stave/pack"
)

// ControlSummary is the minimal control metadata pack resolution needs.
type ControlSummary struct {
	ID       string
	Severity string
}

// CatalogControlSummaries returns the (id, severity) of every control in the
// active catalog — the embedded builtin catalog when useBuiltin is true,
// otherwise the controls under controlsDir. Sorted by ID.
func CatalogControlSummaries(controlsDir string, useBuiltin bool) ([]ControlSummary, error) {
	var out []ControlSummary
	if useBuiltin {
		store := builtin.NewControlStore(controldata.FS, "embedded",
			builtin.WithAliasResolver(predicates.ResolverFunc()))
		controls, err := store.All()
		if err != nil {
			return nil, fmt.Errorf("load builtin control catalog: %w", err)
		}
		out = make([]ControlSummary, 0, len(controls))
		for i := range controls {
			out = append(out, ControlSummary{ID: string(controls[i].ID), Severity: controls[i].Severity.String()})
		}
	} else {
		controls, err := applycore.LoadControls(controlsDir)
		if err != nil {
			return nil, fmt.Errorf("load controls from %q: %w", controlsDir, err)
		}
		out = make([]ControlSummary, 0, len(controls))
		for i := range controls {
			out = append(out, ControlSummary{ID: string(controls[i].ID), Severity: controls[i].Severity.String()})
		}
	}
	slices.SortFunc(out, func(a, b ControlSummary) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

// ResolvePackControls expands one or more concern-pack names into the union of
// their control IDs, resolved against the active catalog. Returns nil for an
// empty packNames (callers then evaluate every control). An unknown pack name
// is an ErrInvalidInput so the CLI maps it to exit 2.
func ResolvePackControls(packNames []string, controlsDir string, useBuiltin bool) ([]string, error) {
	if len(packNames) == 0 {
		return nil, nil
	}
	sums, err := CatalogControlSummaries(controlsDir, useBuiltin)
	if err != nil {
		return nil, err
	}
	metas := make([]pack.ControlMeta, len(sums))
	for i, s := range sums {
		metas[i] = pack.ControlMeta{ID: s.ID, Severity: s.Severity}
	}
	seen := map[string]bool{}
	var ids []string
	for _, name := range packNames {
		p, perr := pack.Load(name)
		if perr != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidInput, perr)
		}
		for _, id := range p.Resolve(metas) {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

// ServiceSeverityCounts is a per-severity control breakdown for one service.
type ServiceSeverityCounts struct {
	Service  string `json:"service"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Info     int    `json:"info"`
	Total    int    `json:"total"`
}

// AutoPlanResult is the resolved plan for an --auto evaluation.
type AutoPlanResult struct {
	Services   []string
	ControlIDs []string
	Counts     []ServiceSeverityCounts
}

// AutoPlanSummary resolves packs and/or services into a plan summary:
// which controls would evaluate and their severity breakdown per service.
func AutoPlanSummary(packNames, services []string, controlsDir string, useBuiltin bool) (*AutoPlanResult, error) {
	sums, err := CatalogControlSummaries(controlsDir, useBuiltin)
	if err != nil {
		return nil, fmt.Errorf("load control catalog: %w", err)
	}
	metas := make([]pack.ControlMeta, len(sums))
	for i, s := range sums {
		metas[i] = pack.ControlMeta{ID: s.ID, Severity: s.Severity}
	}

	seen := map[string]bool{}
	var controlIDs []string
	svcs := append([]string{}, services...)

	if len(packNames) > 0 {
		for _, name := range packNames {
			p, perr := pack.Load(name)
			if perr != nil {
				return nil, fmt.Errorf("load pack %s: %w", name, perr)
			}
			for _, id := range p.Resolve(metas) {
				if !seen[id] {
					seen[id] = true
					controlIDs = append(controlIDs, id)
				}
			}
			if len(svcs) == 0 {
				svcs = pack.ServicesForPack(p, metas)
			}
		}
	} else {
		all, lerr := pack.LoadAll()
		if lerr != nil {
			return nil, fmt.Errorf("load packs: %w", lerr)
		}
		for _, n := range pack.PacksForServices(svcs, all, metas) {
			for _, id := range all[n].Resolve(metas) {
				if !seen[id] {
					seen[id] = true
					controlIDs = append(controlIDs, id)
				}
			}
		}
	}

	if len(svcs) == 0 || len(controlIDs) == 0 {
		return nil, nil
	}

	counts := pack.CountByService(controlIDs, metas, svcs)
	var result []ServiceSeverityCounts
	for svc, c := range counts {
		result = append(result, ServiceSeverityCounts{
			Service: svc, Critical: c.Critical, High: c.High,
			Medium: c.Medium, Low: c.Low, Info: c.Info, Total: c.Total,
		})
	}
	slices.SortFunc(result, func(a, b ServiceSeverityCounts) int { return cmp.Compare(a.Service, b.Service) })

	return &AutoPlanResult{Services: svcs, ControlIDs: controlIDs, Counts: result}, nil
}

// ResolveServiceControls returns the catalog control IDs belonging to any of the
// given AWS services (matched by control-ID domain, e.g. CTL.IAM.* -> iam).
// Empty services returns nil (the caller then evaluates every control). Used by
// `apply --services` for per-service-group evaluation.
func ResolveServiceControls(services []string, controlsDir string, useBuiltin bool) ([]string, error) {
	if len(services) == 0 {
		return nil, nil
	}
	sums, err := CatalogControlSummaries(controlsDir, useBuiltin)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, s := range services {
		want[strings.ToLower(strings.TrimSpace(s))] = true
	}
	var ids []string
	for _, s := range sums {
		if want[pack.ServiceForControlID(s.ID)] {
			ids = append(ids, s.ID)
		}
	}
	return ids, nil
}
