package metadata

import (
	"strings"

	"github.com/sufield/stave/internal/env"
	"github.com/sufield/stave/internal/platform/netutil"
)

// CLI metadata constants.
const (
	// CLIName is the canonical name of the CLI binary.
	CLIName = "stave"

	// OfflineHelpSuffix is appended to command Long descriptions to reinforce the offline guarantee.
	OfflineHelpSuffix = "\n\nOffline-only: reads local files; makes zero network connections; no cloud credentials."

	// CLIProjectConfig is the default project configuration file name.
	CLIProjectConfig = "stave.yaml"
	// CLILockfile is the lock file name used for project integrity.
	CLILockfile = "stave.lock"
)

// IssuesRef returns the issue tracker URL, respecting STAVE_ISSUES_URL
// so airgapped users can point to an internal tracker.
func IssuesRef() string {
	return env.IssuesURL.Value()
}

// DocsRef returns a documentation reference for the given topic.
// If STAVE_DOCS_URL is set, it returns a URL with the topic as fragment.
// Otherwise it returns the public GitHub docs URL.
//
// Reads via env.DocsURL.Value() (matching IssuesRef) rather than
// os.Getenv directly, so the Entry's DefaultValue is honoured if
// one is later added — keeping the env-resolution policy
// centralised in the env package.
//
// Topics are escaped via netutil.EscapeFragment so "/" is preserved
// (hierarchical topic IDs like "guides/getting-started" stay
// hierarchical) while spaces and other unsafe fragment characters
// are encoded. Future cmd-side helpers (JiraRef, TelemetryRef) can
// reuse the same fragment-safe escape rather than re-deriving it.
//
// The fallback used to be `"run 'stave docs search " + topic + "'"`
// — a hint that pointed at a `stave docs` subcommand that has never
// existed. Every error message including this hint sent the user
// chasing a phantom command. The fallback now points at the public
// docs directory on GitHub, which is the authoritative location for
// users without STAVE_DOCS_URL configured.
func DocsRef(topic string) string {
	if topic == "" {
		topic = "troubleshooting"
	}
	if base := strings.TrimSpace(env.DocsURL.Value()); base != "" {
		return base + "#" + netutil.EscapeFragment(topic)
	}
	return defaultDocsURL + "#" + netutil.EscapeFragment(topic)
}

// defaultDocsURL is the GitHub-hosted docs entry point shown in error
// "Help:" lines when STAVE_DOCS_URL is unset. start-here.md exists as
// the reading-order index and is the right landing page for an
// operator who just hit an error.
const defaultDocsURL = "https://github.com/sufield/stave/blob/main/docs/start-here.md"

// Command returns the fully-qualified CLI command string.
func Command(command string) string {
	if command == "" {
		return CLIName
	}
	return CLIName + " " + command
}
