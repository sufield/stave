package contracts

import "fmt"

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
)

// String implements fmt.Stringer (and pflag.Value.String).
func (f OutputFormat) String() string { return string(f) }

// Set implements pflag.Value so Cobra's Flags().Var(&format, ...) can
// fill an OutputFormat-typed field directly. Validates at the flag
// boundary so a typo at invocation time fails fast with a clear
// message; per-command parsers may still impose stricter subsets.
func (f *OutputFormat) Set(value string) error {
	switch OutputFormat(value) {
	case FormatText, FormatJSON, FormatSARIF, FormatMarkdown:
		*f = OutputFormat(value)
		return nil
	}
	return fmt.Errorf("invalid output format %q (supported: text, json, sarif, markdown)", value)
}

// Type implements pflag.Value; used by Cobra to render flag help.
func (f OutputFormat) Type() string { return "string" }

// IsJSON reports whether the format is JSON.
func (f OutputFormat) IsJSON() bool { return f == FormatJSON }

// IsMachineReadable reports whether the format is intended for machine
// consumption (JSON or SARIF). When true, stdout output should be
// preserved even in quiet mode.
func (f OutputFormat) IsMachineReadable() bool { return f == FormatJSON || f == FormatSARIF }
