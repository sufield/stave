package cmdutil

import "github.com/sufield/stave/internal/app/contracts"

// OutputFormat is the CLI's output-format type, re-exported from
// internal/app/contracts so command packages can stay facade-clean —
// they import cmd/cmdutil (CLI infrastructure) instead of internal/.
//
// It is a type ALIAS, so cmdutil.OutputFormat and contracts.OutputFormat
// are the identical type: values flow between cmd/, cmd/cmdutil, and the
// engine without conversion, and the .IsJSON()/.IsText()/… methods come
// along for free. Output format is a CLI-presentation concern, which is
// why it lives here in the wrapper layer rather than in pkg/stave (the
// library returns data; the CLI chooses how to render it).
type OutputFormat = contracts.OutputFormat

// The output-format values, re-exported alongside OutputFormat so a
// facade-clean command can name them without importing internal/.
const (
	FormatText     = contracts.FormatText
	FormatJSON     = contracts.FormatJSON
	FormatSARIF    = contracts.FormatSARIF
	FormatMarkdown = contracts.FormatMarkdown
	FormatTable    = contracts.FormatTable
	FormatCSV      = contracts.FormatCSV
)
