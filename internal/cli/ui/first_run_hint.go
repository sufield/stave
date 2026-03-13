package ui

const (
	// FirstRunHintMessage is the actionable tip shown to new users.
	FirstRunHintMessage = "Tip: run `stave init` to scaffold a starter project."
)

// hintSuppressors defines the set of CLI arguments that, if present,
// will prevent the first-run hint from being displayed.
var hintSuppressors = map[string]struct{}{
	"-h":         {},
	"--help":     {},
	"help":       {},
	"--version":  {},
	"version":    {},
	"completion": {},
}

// ShouldSkipFirstRunHint returns true if any of the provided arguments
// match a known meta-command (e.g., help, version).
func ShouldSkipFirstRunHint(args []string) bool {
	for _, arg := range args {
		if _, suppressed := hintSuppressors[arg]; suppressed {
			return true
		}
	}
	return false
}
