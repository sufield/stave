package contracts

import (
	"fmt"
	"io"
)

// OutputFormat represents a CLI output format.
type OutputFormat string

const (
	// FormatText selects human-readable text output.
	FormatText OutputFormat = "text"
	// FormatJSON selects JSON output.
	FormatJSON OutputFormat = "json"
	// FormatSARIF selects SARIF v2.1.0 output for GitHub Code Scanning.
	FormatSARIF OutputFormat = "sarif"
	// FormatMarkdown selects Markdown output (headings + pipe tables).
	FormatMarkdown OutputFormat = "markdown"
	// FormatTable selects column-aligned table output. Distinct from
	// FormatText: text is paragraph-style human prose; table is a
	// dense grid for one-row-per-record rollups (rank, scorecard,
	// trend). Some commands expose only one of the two.
	FormatTable OutputFormat = "table"
	// FormatCSV selects comma-separated-values output for spreadsheet
	// or pipeline consumption.
	FormatCSV OutputFormat = "csv"
	// FormatHTML selects a self-contained HTML page rendered from markdown.
	FormatHTML OutputFormat = "html"
)

// String implements fmt.Stringer (and pflag.Value.String).
func (f OutputFormat) String() string { return string(f) }

// Set implements pflag.Value so Cobra's Flags().Var(&format, ...) can
// fill an OutputFormat-typed field directly. Validates at the flag
// boundary so a typo at invocation time fails fast with a clear
// message; per-command parsers may still impose stricter subsets.
func (f *OutputFormat) Set(value string) error {
	switch OutputFormat(value) {
	case FormatText, FormatJSON, FormatSARIF, FormatMarkdown, FormatTable, FormatCSV, FormatHTML:
		*f = OutputFormat(value)
		return nil
	}
	return fmt.Errorf("invalid output format %q (supported: text, json, sarif, markdown, table, csv, html)", value)
}

// Type implements pflag.Value; used by Cobra to render flag help.
func (f OutputFormat) Type() string { return "string" }

// IsJSON reports whether the format is JSON.
func (f OutputFormat) IsJSON() bool { return f == FormatJSON }

// IsMarkdown reports whether the format is Markdown.
func (f OutputFormat) IsMarkdown() bool { return f == FormatMarkdown }

// IsText reports whether the format is the human-readable text
// default. Used by commands that branch on "human render or
// machine render".
func (f OutputFormat) IsText() bool { return f == FormatText }

// IsSARIF reports whether the format is SARIF v2.1.0.
func (f OutputFormat) IsSARIF() bool { return f == FormatSARIF }

// IsTable reports whether the format is column-aligned table output.
func (f OutputFormat) IsTable() bool { return f == FormatTable }

// IsCSV reports whether the format is CSV.
func (f OutputFormat) IsCSV() bool { return f == FormatCSV }

// IsMachineReadable reports whether the format is intended for machine
// consumption (JSON or SARIF). When true, stdout output should be
// preserved even in quiet mode.
func (f OutputFormat) IsMachineReadable() bool { return f == FormatJSON || f == FormatSARIF }

// RenderFunc renders a value into w in a specific output format.
// Used by Dispatch as the per-format adapter so commands can
// register a small table of renderers and let the format type
// drive the selection.
type RenderFunc func(w io.Writer) error

// Dispatch picks the renderer matching f from table and runs it,
// falling back to defaultRenderer when no exact match exists. This
// collapses the per-command `switch opts.Format` blocks to a
// single call and keeps the format → renderer wiring close to the
// command's own types.
//
// Pattern:
//
//	return cfg.Format.Dispatch(stdout, contracts.RenderFuncs{
//	    contracts.FormatJSON:     renderJSON,
//	    contracts.FormatMarkdown: renderMarkdown,
//	}, renderText)
//
// defaultRenderer must be non-nil when the table is incomplete;
// passing nil with no matching entry returns an error rather than
// silently writing nothing.
func (f OutputFormat) Dispatch(w io.Writer, table RenderFuncs, defaultRenderer RenderFunc) error {
	if r, ok := table[f]; ok {
		return r(w)
	}
	if defaultRenderer != nil {
		return defaultRenderer(w)
	}
	return fmt.Errorf("no renderer for format %q", string(f))
}

// RenderFuncs is the per-format renderer table consumed by
// OutputFormat.Dispatch.
type RenderFuncs map[OutputFormat]RenderFunc
