package config

import "github.com/sufield/stave/internal/sanitize"

// GlobalSettings is the pure, adapter-free representation of the
// root persistent flags a CLI run resolves at the boundary. It lives
// in internal/config so application and domain code can receive a
// typed value without importing cobra transitively — the adapter
// package cmd/cmdutil/cliflags fills this struct from a
// *cobra.Command and hands it to RunE logic as plain data.
//
// Fields mirror the root flags registered in cmd/root.go. When a new
// global flag is added, extend this struct (and the adapter that
// populates it) rather than reading the flag ad-hoc inside command
// logic — that way the ban on cobra in non-adapter packages keeps
// enforcing itself.
type GlobalSettings struct {
	// Quiet suppresses progress and hint output. Machine-readable
	// formats (JSON, SARIF) remain on stdout.
	Quiet bool

	// Yes auto-confirms interactive prompts.
	Yes bool

	// Force overrides safety checks that would otherwise block
	// destructive operations.
	Force bool

	// Sanitize masks infrastructure identifiers in user-facing
	// output.
	Sanitize bool

	// PathMode chooses between full-path and basename rendering
	// for file references in output.
	PathMode sanitize.PathMode

	// Strict promotes warnings to errors.
	Strict bool

	// LogFile is the path to the session log destination. Empty
	// means no file logging.
	LogFile string

	// RequireOffline refuses execution when the runtime cannot
	// prove it is offline.
	RequireOffline bool

	// AllowSymlinkOut permits symlinks in the output tree.
	AllowSymlinkOut bool

	// AllowUnknownInput accepts observations whose source type is
	// not recognized.
	AllowUnknownInput bool
}

// TextOutputEnabled reports whether human-readable text should be
// printed — inverse of Quiet.
func (g GlobalSettings) TextOutputEnabled() bool { return !g.Quiet }

// AutoConfirm reports whether interactive prompts should be skipped.
// True when --yes is set or (in future) when stderr is not a TTY.
func (g GlobalSettings) AutoConfirm() bool { return g.Yes }

// NewSanitizer constructs a sanitizer configured from these
// settings. Returned value is owned by the caller.
func (g GlobalSettings) NewSanitizer() *sanitize.Sanitizer {
	return sanitize.Policy{
		SanitizeIDs: g.Sanitize,
		PathMode:    g.PathMode,
	}.NewSanitizer()
}
