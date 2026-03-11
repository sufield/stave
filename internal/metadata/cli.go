package metadata

import (
	"os"
	"strings"

	"github.com/sufield/stave/internal/env"
)

const (
	CLIName = "stave"

	// OfflineHelpSuffix is appended to command Long descriptions to reinforce the offline guarantee.
	OfflineHelpSuffix = "\n\nOffline-only: reads local files; makes zero network connections; no cloud credentials."

	CLIProjectConfig = "stave.yaml"
	CLILockfile      = "stave.lock"
)

// IssuesRef returns the issue tracker URL, respecting STAVE_ISSUES_URL
// so airgapped users can point to an internal tracker.
func IssuesRef() string {
	return env.IssuesURL.Value()
}

// DocsRef returns a documentation reference for the given topic.
// If STAVE_DOCS_URL is set, it returns a URL with the topic as fragment.
// Otherwise it returns a local command reference.
func DocsRef(topic string) string {
	if topic == "" {
		topic = "troubleshooting"
	}
	if base := strings.TrimSpace(os.Getenv(env.DocsURL.Name)); base != "" {
		return base + "#" + topic
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
