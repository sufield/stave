package stave

import (
	"errors"
	"strings"

	appcaps "github.com/sufield/stave/internal/app/capabilities"
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

	wantSev := strings.ToUpper(strings.TrimSpace(q.Severity))
	out := make([]SearchHit, 0, len(hits))
	for i := range hits {
		c := hits[i].Capability
		if wantSev != "" && strings.ToUpper(c.Severity) != wantSev {
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
