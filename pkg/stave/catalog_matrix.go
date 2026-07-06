package stave

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/sufield/stave/internal/app/expand"
	"github.com/sufield/stave/internal/core/taxonomy"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// MatrixOptions parameterizes [RenderMatrix].
type MatrixOptions struct {
	ControlsDir string
	Format      string // "json" or "text"/""
}

type matrixOutput struct {
	Summary    []matrixSummaryRow `json:"summary"`
	Gaps       []matrixGapRow     `json:"gaps,omitempty"`
	Services   int                `json:"services"`
	Categories int                `json:"categories"`
}

type matrixSummaryRow struct {
	Category string `json:"category"`
	Services int    `json:"services"`
	Controls int    `json:"controls"`
}

type matrixGapRow struct {
	Category string `json:"category"`
	Service  string `json:"service"`
}

// RenderMatrix builds the taxonomy × service cross-product and
// highlights gap cells where a category covers 3+ services but
// is missing from a particular service.
func RenderMatrix(ctx context.Context, opts MatrixOptions) ([]byte, error) {
	controls, err := loadControlsFromDir(ctx, opts.ControlsDir)
	if err != nil {
		return nil, err
	}

	entries := make([]taxonomy.ControlEntry, 0, len(controls))
	for i := range controls {
		svc := strings.ToLower(expand.ServiceFromControlID(controls[i].ID))
		if svc == "unknown" || svc == "" {
			continue
		}
		entries = append(entries, taxonomy.ControlEntry{
			Service:  svc,
			Taxonomy: controls[i].Taxonomy,
		})
	}

	m := taxonomy.BuildMatrix(entries)
	totals := m.CategoryTotals()
	gaps := m.GapCells()

	// Count services per category
	svcCount := make(map[string]int)
	for _, c := range m.Cells {
		svcCount[string(c.Category)+"\x00"+c.Service] = 1
	}
	svcPerCat := make(map[string]int)
	for key := range svcCount {
		cat, _, _ := strings.Cut(key, "\x00")
		svcPerCat[cat]++
	}

	summary := make([]matrixSummaryRow, 0, len(totals))
	for _, t := range totals {
		summary = append(summary, matrixSummaryRow{
			Category: string(t.Category),
			Services: svcPerCat[string(t.Category)],
			Controls: t.ControlCount,
		})
	}

	gapRows := make([]matrixGapRow, 0, len(gaps))
	for _, g := range gaps {
		gapRows = append(gapRows, matrixGapRow{
			Category: string(g.Category),
			Service:  g.Service,
		})
	}
	slices.SortFunc(gapRows, func(a, b matrixGapRow) int {
		if a.Category != b.Category {
			return cmp.Compare(a.Category, b.Category)
		}
		return cmp.Compare(a.Service, b.Service)
	})

	var buf bytes.Buffer
	if opts.Format == "json" {
		out := matrixOutput{
			Summary:    summary,
			Gaps:       gapRows,
			Services:   len(m.Services),
			Categories: len(m.Categories),
		}
		if err := jsonutil.WriteIndented(&buf, out); err != nil {
			return nil, fmt.Errorf("render matrix: %w", err)
		}
	} else {
		fmt.Fprintf(&buf, "Taxonomy × Service Matrix (%d categories, %d services)\n\n",
			len(m.Categories), len(m.Services))

		tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "CATEGORY\tSERVICES\tCONTROLS")
		for _, s := range summary {
			fmt.Fprintf(tw, "%s\t%d\t%d\n", s.Category, s.Services, s.Controls)
		}
		_ = tw.Flush()

		if len(gapRows) > 0 {
			fmt.Fprintf(&buf, "\nGap Cells (%d) — category covers 3+ services but is missing here:\n\n", len(gapRows))
			tw = tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "CATEGORY\tMISSING SERVICE")
			for _, g := range gapRows {
				fmt.Fprintf(tw, "%s\t%s\n", g.Category, g.Service)
			}
			_ = tw.Flush()
		}
	}
	return buf.Bytes(), nil
}
