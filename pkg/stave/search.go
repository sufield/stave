package stave

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	appcaps "github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// SearchHit is one ranked capability returned by [SearchCatalog].
// It re-exports the internal capability record so callers depend
// only on pkg/stave.
type SearchHit struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	UseWhen     string   `json:"use_when,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	AssetTypes  []string `json:"asset_types,omitempty"`
	ControlIDs  []string `json:"control_ids,omitempty"`
	ChainIDs    []string `json:"chain_ids,omitempty"`
	ExampleCmd  string   `json:"example_command,omitempty"`
	Score       float64  `json:"score"`
}

// SearchQuery parameterizes a catalog search.
//
// Severity, when set, filters to capabilities at that severity
// (case-insensitive: CRITICAL/HIGH/MEDIUM/LOW). Limit caps the
// number of hits returned; <= 0 means no cap.
//
// The search runs over the embedded builtin control catalog
// aggregated into capability records plus the operational-feature
// list. Compound-chain entries are not included — they require a
// chains directory, which this offline accessor does not load.
// Framework-scoped queries belong to [Compliance], not here:
// capability records carry no framework mapping.
type SearchQuery struct {
	Query    string
	Severity string
	Limit    int
}

// SearchCatalog ranks the embedded capability catalog against the
// query, expanding synonyms so callers need not know Stave's
// vocabulary first. It is deterministic and offline.
func SearchCatalog(q SearchQuery) ([]SearchHit, error) {
	if strings.TrimSpace(q.Query) == "" {
		return nil, errors.New("stave.SearchCatalog: Query is required")
	}

	controls, err := builtinControls()
	if err != nil {
		return nil, err
	}

	catalog := appcaps.Build(controls, nil)
	hits := appcaps.Rank(catalog, q.Query)

	wantSev := strings.TrimSpace(q.Severity)
	out := make([]SearchHit, 0, len(hits))
	for i := range hits {
		c := hits[i].Capability
		if wantSev != "" && !strings.EqualFold(c.Severity, wantSev) {
			continue
		}
		out = append(out, SearchHit{
			ID:          c.ID,
			Kind:        c.Kind,
			Title:       c.Title,
			Description: c.Description,
			UseWhen:     c.UseWhen,
			Severity:    c.Severity,
			AssetTypes:  c.AssetTypes,
			ControlIDs:  c.ControlIDs,
			ChainIDs:    c.ChainIDs,
			ExampleCmd:  c.ExampleCmd,
			Score:       hits[i].Score,
		})
		if q.Limit > 0 && len(out) >= q.Limit {
			break
		}
	}
	return out, nil
}

// searchRenderReport is the JSON-shape contract for the rendered search
// output. It carries the internal capability hit type directly so the
// JSON is byte-identical to the pre-facade `stave search` output.
type searchRenderReport struct {
	Query string        `json:"query"`
	Top   int           `json:"top"`
	Total int           `json:"total_hits"`
	Hits  []appcaps.Hit `json:"hits"`
}

// RenderCatalogSearch ranks the capability catalog (built from the control
// catalog in controlsDir plus the chains in chainsDir) against the query,
// truncates to top hits, and renders the result as "json" or "text"/"".
// Unlike [SearchCatalog] this loads from directories and includes compound
// chains in the catalog. Loader failures stay plain (exit 4). It is the
// library entry point behind `stave search`.
func RenderCatalogSearch(ctx context.Context, query string, top int, controlsDir, chainsDir, format string) ([]byte, error) {
	controls, err := loadControlsFromDir(ctx, controlsDir)
	if err != nil {
		return nil, err
	}
	chains, err := loadChainsOptional(chainsDir)
	if err != nil {
		return nil, err
	}

	catalog := appcaps.Build(controls, chains)
	hits := appcaps.Rank(catalog, query)
	if len(hits) > top {
		hits = hits[:top]
	}

	report := searchRenderReport{
		Query: query,
		Top:   top,
		Total: len(hits),
		Hits:  hits,
	}

	var buf bytes.Buffer
	if format == "json" {
		if err := jsonutil.WriteIndented(&buf, report); err != nil {
			return nil, fmt.Errorf("render search results: %w", err)
		}
	} else {
		renderSearchText(&buf, report.Query, report.Hits)
	}
	return buf.Bytes(), nil
}

func renderSearchText(w io.Writer, query string, hits []appcaps.Hit) {
	if len(hits) == 0 {
		fmt.Fprintf(w, "No matches for %q. Try broader terms (e.g. \"s3\" instead of \"bucket policy\").\n", query)
		return
	}
	fmt.Fprintf(w, "Matches for %q (%d):\n\n", query, len(hits))
	for i := range hits {
		c := &hits[i].Capability
		fmt.Fprintf(w, "#%d  %s", i+1, c.Title)
		if c.Severity != "" {
			fmt.Fprintf(w, "   [%s]", strings.ToUpper(c.Severity))
		}
		fmt.Fprintln(w)
		if c.UseWhen != "" {
			fmt.Fprintf(w, "    Use when: %s\n", c.UseWhen)
		}
		if c.Description != "" {
			fmt.Fprintf(w, "    Detects:  %s\n", c.Description)
		}
		if c.ExampleCmd != "" {
			fmt.Fprintf(w, "    Command:  %s\n", c.ExampleCmd)
		}
		if len(c.ControlIDs) > 0 {
			n := len(c.ControlIDs)
			limit := min(n, 3)
			extra := ""
			if n > limit {
				extra = fmt.Sprintf(" (+%d more)", n-limit)
			}
			fmt.Fprintf(w, "    Controls: %s%s\n", strings.Join(c.ControlIDs[:limit], ", "), extra)
		}
		if len(c.ChainIDs) > 0 {
			fmt.Fprintf(w, "    Chains:   %s\n", strings.Join(c.ChainIDs, ", "))
		}
		fmt.Fprintln(w)
	}
}
