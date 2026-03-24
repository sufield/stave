package contracts

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

// String implements fmt.Stringer.
func (f OutputFormat) String() string { return string(f) }

// IsJSON reports whether the format is JSON.
func (f OutputFormat) IsJSON() bool { return f == FormatJSON }
