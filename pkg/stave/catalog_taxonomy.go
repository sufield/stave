package stave

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"slices"
	"text/tabwriter"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/taxonomy"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// TaxonomyOptions parameterizes [RenderTaxonomy].
type TaxonomyOptions struct {
	ControlsDir string
	Format      string // "json" or "text"/""
}

type taxonomyEntry struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Count    int    `json:"count"`
}

// RenderTaxonomy lists taxonomy categories with control counts.
func RenderTaxonomy(ctx context.Context, opts TaxonomyOptions) ([]byte, error) {
	controls, err := loadControlsFromDir(ctx, opts.ControlsDir)
	if err != nil {
		return nil, err
	}

	counts := map[string]int{}
	for i := range controls {
		for _, t := range controls[i].Taxonomy {
			counts[string(t)]++
		}
	}

	entries := make([]taxonomyEntry, 0, len(counts))
	for cat, n := range counts {
		entries = append(entries, taxonomyEntry{
			Category: cat,
			Name:     taxonomy.CategoryName(kernel.CategoryID(cat)),
			Count:    n,
		})
	}
	slices.SortFunc(entries, func(a, b taxonomyEntry) int {
		if a.Count != b.Count {
			return cmp.Compare(b.Count, a.Count) // descending
		}
		return cmp.Compare(a.Category, b.Category)
	})

	var buf bytes.Buffer
	if opts.Format == "json" {
		if err := jsonutil.WriteIndented(&buf, entries); err != nil {
			return nil, fmt.Errorf("render taxonomy: %w", err)
		}
	} else {
		fmt.Fprintf(&buf, "Taxonomy Categories (%d)\n\n", len(entries))
		tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "CATEGORY\tNAME\tCONTROLS")
		for i := range entries {
			fmt.Fprintf(tw, "%s\t%s\t%d\n", entries[i].Category, entries[i].Name, entries[i].Count)
		}
		_ = tw.Flush()
	}
	return buf.Bytes(), nil
}
