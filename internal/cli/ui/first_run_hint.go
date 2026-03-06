package ui

// FirstRunHintMessage is the hint shown on the first CLI invocation.
const FirstRunHintMessage = "Tip: run `stave init` to scaffold a starter project."

var metaCommands = map[string]bool{
	"-h": true, "--help": true, "help": true,
	"--version": true, "version": true, "completion": true,
}

// ShouldSkipFirstRunHint reports whether args contain a meta command
// (help, version, completion) that should suppress the first-run hint.
func ShouldSkipFirstRunHint(args []string) bool {
	for _, a := range args {
		if metaCommands[a] {
			return true
		}
	}
	return false
}
