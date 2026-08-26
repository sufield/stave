package stave

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/util/jsonutil"
	"gopkg.in/yaml.v3"
)

// CatalogGapsOptions parameterizes [RenderCatalogGaps].
type CatalogGapsOptions struct {
	ChecklistPath string
	ControlsDir   string
	Format        string // "json" or "text"/""
	Strict        bool   // exact ID match only, no fuzzy
}

// ChecklistFile is the on-disk YAML shape for an external checklist.
type ChecklistFile struct {
	Checks []ChecklistItem `yaml:"checks" json:"checks"`
}

// ChecklistItem is one item in the external checklist.
type ChecklistItem struct {
	ID            string   `yaml:"id"             json:"id"`
	Service       string   `yaml:"service"        json:"service"`
	Description   string   `yaml:"description"    json:"description"`
	Reference     string   `yaml:"reference"      json:"reference"`
	PredicatePath []string `yaml:"predicate_path" json:"predicate_path,omitempty"`
}

type catalogGapsReport struct {
	Total      int              `json:"total"`
	Covered    int              `json:"covered"`
	Uncovered  int              `json:"uncovered"`
	Ambiguous  int              `json:"ambiguous"`
	Candidates int              `json:"candidates"`
	Items      []catalogGapItem `json:"items"`
}

type catalogGapItem struct {
	CheckID     string `json:"check_id"`
	Service     string `json:"service"`
	Description string `json:"description"`
	Reference   string `json:"reference,omitempty"`
	Status      string `json:"status"` // "covered", "uncovered", "ambiguous"
	MatchedID   string `json:"matched_control,omitempty"`
}

type gapControlEntry struct {
	id      string
	service string
	name    string
	desc    string
	paths   []string // predicate field paths (properties.X.Y)
}

// RenderCatalogGaps loads an external checklist and compares it against
// the catalog, reporting which items have matching controls and which
// are uncovered.
func RenderCatalogGaps(ctx context.Context, opts CatalogGapsOptions) ([]byte, error) {
	if opts.ChecklistPath == "" {
		return nil, fmt.Errorf("checklist file is required: %w", ErrInvalidInput)
	}

	data, err := fsutil.ReadFileLimited(opts.ChecklistPath)
	if err != nil {
		return nil, fmt.Errorf("read checklist %q: %w", opts.ChecklistPath, err)
	}
	var checklist ChecklistFile
	if uerr := yaml.Unmarshal(data, &checklist); uerr != nil {
		return nil, fmt.Errorf("parse checklist %q: %w", opts.ChecklistPath, uerr)
	}
	if len(checklist.Checks) == 0 {
		return nil, fmt.Errorf("checklist %q has no checks: %w", opts.ChecklistPath, ErrInvalidInput)
	}

	controls, err := loadControlsFromDir(ctx, opts.ControlsDir)
	if err != nil {
		return nil, err
	}

	indexed := make([]gapControlEntry, 0, len(controls))
	for i := range controls {
		svc, _ := catalogParseControlID(string(controls[i].ID))
		indexed = append(indexed, gapControlEntry{
			id:      string(controls[i].ID),
			service: svc,
			name:    strings.ToLower(controls[i].Name),
			desc:    strings.ToLower(controls[i].Description),
			paths:   predicateFieldPaths(&controls[i].UnsafePredicate),
		})
	}

	items := make([]catalogGapItem, 0, len(checklist.Checks))
	var covered, uncovered, ambiguous, candidates int
	for _, check := range checklist.Checks {
		item := catalogGapItem{
			CheckID:     check.ID,
			Service:     check.Service,
			Description: check.Description,
			Reference:   check.Reference,
		}

		matchID, status := matchControl(check, indexed, opts.Strict)
		item.Status = status
		item.MatchedID = matchID

		switch status {
		case "covered":
			covered++
		case "ambiguous":
			ambiguous++
		case "candidate":
			candidates++
		default:
			uncovered++
		}
		items = append(items, item)
	}

	report := catalogGapsReport{
		Total:      len(checklist.Checks),
		Covered:    covered,
		Uncovered:  uncovered,
		Ambiguous:  ambiguous,
		Candidates: candidates,
		Items:      items,
	}

	var buf bytes.Buffer
	if opts.Format == "json" {
		if err := jsonutil.WriteIndented(&buf, report); err != nil {
			return nil, fmt.Errorf("render catalog gaps: %w", err)
		}
	} else {
		renderCatalogGapsText(&buf, report)
	}
	return buf.Bytes(), nil
}

func matchControl(check ChecklistItem, controls []gapControlEntry, strict bool) (string, string) {
	checkSvc := strings.ToLower(check.Service)
	checkDesc := strings.ToLower(check.Description)

	if strict {
		for _, c := range controls {
			if strings.EqualFold(c.id, check.ID) {
				return c.id, "covered"
			}
		}
		return "", "uncovered"
	}

	// Path-based deterministic matching when checklist item has predicate_path.
	if len(check.PredicatePath) > 0 {
		var matches []string
		for _, c := range controls {
			if matchesAnyPath(c.paths, check.PredicatePath) {
				matches = append(matches, c.id)
			}
		}
		slices.SortFunc(matches, func(a, b string) int { return cmp.Compare(a, b) })
		switch len(matches) {
		case 0:
			return "", "uncovered"
		case 1:
			return matches[0], "covered"
		default:
			return matches[0], "covered"
		}
	}

	// Fuzzy fallback for items without predicate_path — results are candidates only.
	var matches []string
	for _, c := range controls {
		if checkSvc != "" && c.service != checkSvc {
			continue
		}
		if keywordOverlap(checkDesc, c.name+" "+c.desc) >= 3 {
			matches = append(matches, c.id)
		}
	}
	slices.SortFunc(matches, func(a, b string) int { return cmp.Compare(a, b) })

	switch len(matches) {
	case 0:
		return "", "uncovered"
	case 1:
		return matches[0], "candidate"
	default:
		return matches[0], "candidate"
	}
}

func matchesAnyPath(controlPaths, wantPaths []string) bool {
	for _, want := range wantPaths {
		if slices.Contains(controlPaths, strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

func predicateFieldPaths(p *controldef.UnsafePredicate) []string {
	if p == nil {
		return nil
	}
	seen := map[string]struct{}{}
	p.Walk(func(r controldef.PredicateRule) {
		s := r.Field.String()
		if s != "" {
			seen[s] = struct{}{}
		}
	})
	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	return paths
}

var gapStopWords = map[string]bool{
	"the": true, "and": true, "for": true, "with": true, "from": true,
	"this": true, "that": true, "are": true, "not": true, "must": true,
	"any": true, "all": true, "has": true, "have": true, "had": true,
	"does": true, "should": true, "will": true, "can": true, "may": true,
	"its": true, "into": true, "out": true, "via": true, "use": true,
	"used": true, "uses": true, "been": true, "being": true, "also": true,
	"when": true, "each": true, "which": true, "their": true, "they": true,
}

func cleanWord(w string) string {
	return strings.Trim(w, ".,;:!?\"'()[]{} ")
}

func keywordOverlap(a, b string) int {
	wordsA := strings.Fields(a)
	setB := map[string]struct{}{}
	for w := range strings.FieldsSeq(b) {
		w = cleanWord(w)
		if len(w) >= 3 && !gapStopWords[w] {
			setB[w] = struct{}{}
		}
	}
	count := 0
	for _, w := range wordsA {
		w = cleanWord(w)
		if len(w) < 3 || gapStopWords[w] {
			continue
		}
		if _, ok := setB[w]; ok {
			count++
		}
	}
	return count
}

func renderCatalogGapsText(buf *bytes.Buffer, r catalogGapsReport) {
	fmt.Fprintf(buf, "Catalog Gap Analysis: %d checks — %d covered, %d uncovered",
		r.Total, r.Covered, r.Uncovered)
	if r.Candidates > 0 {
		fmt.Fprintf(buf, ", %d candidates", r.Candidates)
	}
	if r.Ambiguous > 0 {
		fmt.Fprintf(buf, ", %d ambiguous", r.Ambiguous)
	}
	fmt.Fprintln(buf)
	fmt.Fprintln(buf)

	tw := tabwriter.NewWriter(buf, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tCHECK ID\tSERVICE\tMATCHED CONTROL\tDESCRIPTION")
	for i := range r.Items {
		item := &r.Items[i]
		marker := "  "
		switch item.Status {
		case "covered":
			marker = "OK"
		case "candidate":
			marker = "~ "
		case "ambiguous":
			marker = "? "
		case "uncovered":
			marker = "  "
		}
		desc := item.Description
		if len(desc) > 50 {
			desc = desc[:47] + "..."
		}
		matched := item.MatchedID
		if matched == "" {
			matched = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			marker, item.CheckID, strings.ToUpper(item.Service), matched, desc)
	}
	_ = tw.Flush()
}
