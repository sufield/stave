package nep

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/platform/providers/aws/iam"
)

// `stave nep` is one command with three subcommands — principal,
// resource, summary — each rendering a different payload type. Each
// subcommand gets its own Renderer interface keyed by the payload it
// renders; the factories share the format-string contract but the
// concrete types and dispatch tables are per-mode. Same shape as
// cmd/consolidate from batch 9.

// --- PrincipalRenderer ---

// PrincipalRenderer renders the per-principal NEP resolution result.
// TableRenderer carries the principalOpts because the table needs
// flag state (e.g. boundary display) that isn't part of the result.
type PrincipalRenderer interface {
	Render(w io.Writer, result iam.ResolvedPermissions) error
}

// PrincipalJSONRenderer encodes the resolved permissions as JSON.
type PrincipalJSONRenderer struct{}

// Render implements PrincipalRenderer.
func (PrincipalJSONRenderer) Render(w io.Writer, result iam.ResolvedPermissions) error {
	return renderPrincipalJSON(w, result)
}

// PrincipalTableRenderer writes the default human-readable table.
type PrincipalTableRenderer struct {
	Opts *principalOpts
}

// Render implements PrincipalRenderer.
func (r PrincipalTableRenderer) Render(w io.Writer, result iam.ResolvedPermissions) error {
	return renderPrincipalTable(w, result, r.Opts)
}

// NewPrincipalRenderer maps a format string to its concrete renderer.
func NewPrincipalRenderer(format string, opts *principalOpts) (PrincipalRenderer, error) {
	switch format {
	case "json":
		return PrincipalJSONRenderer{}, nil
	case "table", "":
		return PrincipalTableRenderer{Opts: opts}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json)", format)
}

// --- ResourceRenderer ---

// ResourcePayload bundles the data each resource-mode renderer
// needs. JSON/Table operate on DisplayEntries (the filtered view);
// DOT renders the full graph from AllEntries + Designated. All
// three need the resource ARN and the ShowDesignated flag.
type ResourcePayload struct {
	ResourceARN     string
	DisplayEntries  []iam.ResourceAccessEntry
	AllEntries      []iam.ResourceAccessEntry
	Designated      map[string]bool
	ShowDesignated  bool
}

// ResourceRenderer renders the per-resource NEP entries view.
type ResourceRenderer interface {
	Render(w io.Writer, p ResourcePayload) error
}

// ResourceJSONRenderer encodes the displayed entries as JSON.
type ResourceJSONRenderer struct{}

// Render implements ResourceRenderer.
func (ResourceJSONRenderer) Render(w io.Writer, p ResourcePayload) error {
	return renderResourceJSON(w, p.ResourceARN, p.DisplayEntries, p.ShowDesignated)
}

// ResourceTableRenderer writes the default human-readable table.
type ResourceTableRenderer struct{}

// Render implements ResourceRenderer.
func (ResourceTableRenderer) Render(w io.Writer, p ResourcePayload) error {
	return renderResourceTable(w, p.ResourceARN, p.DisplayEntries, p.ShowDesignated)
}

// ResourceDOTRenderer emits the Graphviz DOT representation of the
// full (unfiltered) access graph annotated with the designated set.
type ResourceDOTRenderer struct{}

// Render implements ResourceRenderer.
func (ResourceDOTRenderer) Render(w io.Writer, p ResourcePayload) error {
	return renderResourceDOT(w, p.ResourceARN, p.AllEntries, p.Designated, p.ShowDesignated)
}

// NewResourceRenderer maps a format string to its concrete renderer.
func NewResourceRenderer(format string) (ResourceRenderer, error) {
	switch format {
	case "json":
		return ResourceJSONRenderer{}, nil
	case "dot":
		return ResourceDOTRenderer{}, nil
	case "table", "":
		return ResourceTableRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json | dot)", format)
}

// --- SummaryRenderer ---

// SummaryRenderer renders the NEP summary view. TableRenderer
// carries the summaryOpts because the table format references
// flag state (e.g. snapshot path) that isn't part of the summary.
type SummaryRenderer interface {
	Render(w io.Writer, summary nepSummary) error
}

// SummaryJSONRenderer encodes the summary as JSON.
type SummaryJSONRenderer struct{}

// Render implements SummaryRenderer.
func (SummaryJSONRenderer) Render(w io.Writer, summary nepSummary) error {
	return renderSummaryJSON(w, summary)
}

// SummaryTableRenderer writes the default human-readable table.
type SummaryTableRenderer struct {
	Opts *summaryOpts
}

// Render implements SummaryRenderer.
func (r SummaryTableRenderer) Render(w io.Writer, summary nepSummary) error {
	return renderSummaryTable(w, summary, r.Opts)
}

// NewSummaryRenderer maps a format string to its concrete renderer.
func NewSummaryRenderer(format string, opts *summaryOpts) (SummaryRenderer, error) {
	switch format {
	case "json":
		return SummaryJSONRenderer{}, nil
	case "table", "":
		return SummaryTableRenderer{Opts: opts}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json)", format)
}
