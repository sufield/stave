package main

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"html"
	"slices"
	"strings"
	"text/template"

	"github.com/sufield/stave/pkg/stave"
)

// Chain-graph layout geometry (SVG user units).
const (
	chNodeW  = 170
	chNodeH  = 58
	chGapX   = 46
	chGapY   = 80
	chPerRow = 4
	chMargin = 16
)

// nodePalette colors leg nodes by service, hashed deterministically so
// the same service is always the same color across chains.
var nodePalette = []string{
	"#3B82F6", "#F97316", "#A855F7", "#22C55E",
	"#EAB308", "#06B6D4", "#EC4899", "#14B8A6",
}

// chainsView is the escape-safe data the chains template renders. As
// with the other renderers, free text is HTML-escaped during prep and
// numbers/enums are produced here, so text/template is safe. This
// renderer is independent of dashboard.go and scorecard.go.
type chainsView struct {
	Total     int
	SevCounts []chainSev
	Chains    []chainCard
}

type chainSev struct {
	Label string
	Count int
	Color string
	Has   bool
}

type chainCard struct {
	TabID       string
	ID          string
	Severity    string
	SevColor    string
	Score       string
	Description string
	Narrative   string
	Stages      string
	AssetCount  int
	Active      bool
	Legs        []legNode
	Arrows      []arrow
	Term        termNode
	SVGW        int
	SVGH        int
}

type legNode struct {
	X, Y      int
	W, H      int
	Label     string
	Asset     string
	ControlID string
	Color     string
}

type termNode struct {
	X, Y  int
	W, H  int
	Label string
	Color string
}

type arrow struct {
	X1, Y1, X2, Y2 int
}

// renderChains returns a complete, self-contained HTML chain
// visualizer: a summary bar, a clickable chain list, and per-chain a
// left-to-right SVG graph of the compound legs (the co-failing
// controls) flowing into a compound-risk node. All CSS/JS/SVG inline.
func renderChains(assessment *stave.Assessment) (string, error) {
	if len(assessment.ChainFindings) == 0 {
		return "", errors.New("renderChains: no chain findings")
	}
	view := buildChainsView(assessment)
	tmpl, err := template.New("chains").
		Funcs(template.FuncMap{"add": func(a, b int) int { return a + b }}).
		Parse(chainsHTML)
	if err != nil {
		return "", fmt.Errorf("parse chains template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, view); err != nil {
		return "", fmt.Errorf("render chains: %w", err)
	}
	return buf.String(), nil
}

// buildChainsView projects the assessment's chain findings into the
// escape-safe view model, computing the SVG layout for each chain.
func buildChainsView(a *stave.Assessment) chainsView {
	chains := make([]stave.ChainFinding, len(a.ChainFindings))
	copy(chains, a.ChainFindings)
	slices.SortStableFunc(chains, func(a, b stave.ChainFinding) int {
		return cmp.Compare(severityRank(b.Severity), severityRank(a.Severity))
	})

	var v chainsView
	v.Total = len(chains)
	v.SevCounts = chainSeverityCounts(chains)

	for i := range chains {
		c := &chains[i]
		ctrlAsset, assets := chainAssets(a, c.ChainID)

		card := chainCard{
			TabID:       fmt.Sprintf("chain%d", i),
			ID:          html.EscapeString(string(c.ChainID)),
			Severity:    string(c.Severity),
			SevColor:    severityColor(c.Severity),
			Score:       fmt.Sprintf("%.0f", c.CompoundScore),
			Description: html.EscapeString(c.Description),
			Narrative:   html.EscapeString(c.Narrative),
			Stages:      html.EscapeString(strings.Join(c.AttackStages, " → ")),
			AssetCount:  len(assets),
			Active:      i == 0,
		}
		card.layoutGraph(c, ctrlAsset)
		v.Chains = append(v.Chains, card)
	}
	return v
}

// layoutGraph fills the leg nodes, arrows, terminal node, and SVG
// canvas size for a chain card from its failing controls.
func (card *chainCard) layoutGraph(c *stave.ChainFinding, ctrlAsset map[string]string) {
	n := len(c.ControlsFailing)
	// Node positions: legs 0..n-1, then the terminal compound node at n.
	for idx, ctl := range c.ControlsFailing {
		x, y := nodePos(idx)
		ctlID := string(ctl)
		card.Legs = append(card.Legs, legNode{
			X: x, Y: y, W: chNodeW, H: chNodeH,
			Label:     html.EscapeString(shortControl(ctlID)),
			Asset:     html.EscapeString(shortAsset(ctrlAsset[ctlID])),
			ControlID: html.EscapeString(ctlID),
			Color:     serviceColor(ctlID),
		})
	}
	tx, ty := nodePos(n)
	card.Term = termNode{X: tx, Y: ty, W: chNodeW, H: chNodeH, Label: "COMPOUND RISK", Color: card.SevColor}

	// Arrows connect consecutive legs, then last leg → terminal.
	positions := n + 1
	for idx := 0; idx < positions-1; idx++ {
		card.Arrows = append(card.Arrows, edge(idx, idx+1))
	}

	rows := (positions + chPerRow - 1) / chPerRow
	card.SVGW = chMargin*2 + chPerRow*(chNodeW+chGapX) - chGapX
	card.SVGH = chMargin*2 + rows*(chNodeH+chGapY) - chGapY
}

// nodePos returns the top-left (x,y) for the idx-th node, wrapping
// every chPerRow nodes onto a new row.
func nodePos(idx int) (int, int) {
	col := idx % chPerRow
	row := idx / chPerRow
	x := chMargin + col*(chNodeW+chGapX)
	y := chMargin + row*(chNodeH+chGapY)
	return x, y
}

// edge computes the arrow between node a and node b: a horizontal
// right→left link when on the same row, otherwise a bottom→top link.
func edge(a, b int) arrow {
	ax, ay := nodePos(a)
	bx, by := nodePos(b)
	if ay == by {
		return arrow{X1: ax + chNodeW, Y1: ay + chNodeH/2, X2: bx, Y2: by + chNodeH/2}
	}
	return arrow{X1: ax + chNodeW/2, Y1: ay + chNodeH, X2: bx + chNodeW/2, Y2: by}
}

// chainAssets maps each failing control to the asset it fired on (from
// member findings) and returns the distinct participating asset set.
// Marker chains with no member findings yield empty maps — honest.
func chainAssets(a *stave.Assessment, chainID stave.ChainID) (map[string]string, map[string]bool) {
	ctrlAsset := map[string]string{}
	assets := map[string]bool{}
	for i := range a.Findings {
		f := &a.Findings[i]
		for _, m := range f.ChainMembership {
			if m.ChainID == chainID {
				ctrlAsset[string(f.ControlID)] = string(f.AssetID)
				assets[string(f.AssetID)] = true
			}
		}
	}
	return ctrlAsset, assets
}

// chainSeverityCounts tallies chains by severity in fixed order.
func chainSeverityCounts(chains []stave.ChainFinding) []chainSev {
	counts := map[stave.Severity]int{}
	for i := range chains {
		counts[chains[i].Severity]++
	}
	out := make([]chainSev, 0, 4)
	for _, o := range []struct {
		sev   stave.Severity
		label string
	}{
		{stave.SeverityCritical, "CRITICAL"},
		{stave.SeverityHigh, "HIGH"},
		{stave.SeverityMedium, "MEDIUM"},
		{stave.SeverityLow, "LOW"},
	} {
		n := counts[o.sev]
		out = append(out, chainSev{Label: o.label, Count: n, Color: severityColor(o.sev), Has: n > 0})
	}
	return out
}

// serviceColor maps a control ID's service segment (CTL.<SVC>.…) to a
// stable palette color.
func serviceColor(controlID string) string {
	svc := ""
	if parts := strings.Split(controlID, "."); len(parts) >= 2 && parts[0] == "CTL" {
		svc = parts[1]
	}
	h := 0
	for _, r := range svc {
		h = h*31 + int(r)
	}
	if h < 0 {
		h = -h
	}
	return nodePalette[h%len(nodePalette)]
}

// shortControl strips the CTL. prefix and truncates for the node label.
func shortControl(id string) string {
	s := strings.TrimPrefix(id, "CTL.")
	if len(s) > 26 {
		s = s[:25] + "…"
	}
	return s
}

// shortAsset truncates an asset ID to its trailing segment for display.
func shortAsset(id string) string {
	if id == "" {
		return ""
	}
	if i := strings.LastIndex(id, ":"); i >= 0 && i+1 < len(id) {
		id = id[i+1:]
	}
	if len(id) > 24 {
		id = id[:23] + "…"
	}
	return id
}
