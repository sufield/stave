package taxonomy

import (
	"cmp"
	"slices"

	"github.com/sufield/stave/internal/core/kernel"
)

// MatrixCell represents coverage of one category in one service.
type MatrixCell struct {
	Category     kernel.CategoryID `json:"category"`
	Service      string            `json:"service"`
	ControlCount int               `json:"control_count"`
}

// Matrix is the taxonomy × service cross-product.
type Matrix struct {
	Cells      []MatrixCell        `json:"cells"`
	Categories []kernel.CategoryID `json:"categories"`
	Services   []string            `json:"services"`
}

// ControlEntry is the input to BuildMatrix — a control's service
// and its taxonomy tags.
type ControlEntry struct {
	Service  string
	Taxonomy []kernel.CategoryID
}

// BuildMatrix constructs the taxonomy × service cross-product.
func BuildMatrix(controls []ControlEntry) *Matrix {
	counts := make(map[kernel.CategoryID]map[string]int)
	serviceSet := make(map[string]bool)
	catSet := make(map[kernel.CategoryID]bool)

	for _, c := range controls {
		serviceSet[c.Service] = true
		for _, cat := range c.Taxonomy {
			catSet[cat] = true
			if counts[cat] == nil {
				counts[cat] = make(map[string]int)
			}
			counts[cat][c.Service]++
		}
	}

	m := &Matrix{}
	for s := range serviceSet {
		m.Services = append(m.Services, s)
	}
	slices.Sort(m.Services)

	for c := range catSet {
		m.Categories = append(m.Categories, c)
	}
	slices.SortFunc(m.Categories, func(a, b kernel.CategoryID) int {
		return cmp.Compare(string(a), string(b))
	})

	for cat, services := range counts {
		for svc, count := range services {
			m.Cells = append(m.Cells, MatrixCell{
				Category:     cat,
				Service:      svc,
				ControlCount: count,
			})
		}
	}
	slices.SortFunc(m.Cells, func(a, b MatrixCell) int {
		if a.Category != b.Category {
			return cmp.Compare(string(a.Category), string(b.Category))
		}
		return cmp.Compare(a.Service, b.Service)
	})

	return m
}

// GapCells returns (category, service) pairs where the category
// applies to 3+ services but this service has zero controls.
func (m *Matrix) GapCells() []MatrixCell {
	covered := make(map[kernel.CategoryID]map[string]bool)
	for _, cell := range m.Cells {
		if covered[cell.Category] == nil {
			covered[cell.Category] = make(map[string]bool)
		}
		covered[cell.Category][cell.Service] = true
	}

	var gaps []MatrixCell
	for cat, services := range covered {
		if len(services) < 3 {
			continue
		}
		for _, s := range m.Services {
			if !services[s] {
				gaps = append(gaps, MatrixCell{
					Category:     cat,
					Service:      s,
					ControlCount: 0,
				})
			}
		}
	}
	slices.SortFunc(gaps, func(a, b MatrixCell) int {
		if a.Category != b.Category {
			return cmp.Compare(string(a.Category), string(b.Category))
		}
		return cmp.Compare(a.Service, b.Service)
	})
	return gaps
}

// CategoryTotals returns per-category control counts, sorted descending.
func (m *Matrix) CategoryTotals() []MatrixCell {
	totals := make(map[kernel.CategoryID]int)
	for _, c := range m.Cells {
		totals[c.Category] += c.ControlCount
	}
	out := make([]MatrixCell, 0, len(totals))
	for cat, n := range totals {
		out = append(out, MatrixCell{Category: cat, ControlCount: n})
	}
	slices.SortFunc(out, func(a, b MatrixCell) int {
		if a.ControlCount != b.ControlCount {
			return cmp.Compare(b.ControlCount, a.ControlCount)
		}
		return cmp.Compare(string(a.Category), string(b.Category))
	})
	return out
}
