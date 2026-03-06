package ui

// ShouldEmitOutput reports whether user-facing output should be emitted.
func ShouldEmitOutput(commandQuiet, globalQuiet bool) bool {
	return !commandQuiet && !globalQuiet
}
