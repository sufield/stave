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
// Otherwise it returns a local command reference.
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
func DocsRef(topic string) string {
	if topic == "" {
		topic = "troubleshooting"
	}
	if base := strings.TrimSpace(env.DocsURL.Value()); base != "" {
		return base + "#" + netutil.EscapeFragment(topic)
	}
	return "run 'stave docs search " + topic + "'"
}

// Command returns the fully-qualified CLI command string.
func Command(command string) string {
	if command == "" {
		return CLIName
	}
	return CLIName + " " + command
}
