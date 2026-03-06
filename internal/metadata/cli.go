package metadata

import (
	"os"
	"strings"

	"github.com/sufield/stave/internal/envvar"
)

const (
	CLIName = "stave"

	// OfflineHelpSuffix is appended to command Long descriptions to reinforce the offline guarantee.
	OfflineHelpSuffix = "\n\nOffline-only: reads local files; makes zero network connections; no cloud credentials."

	CLIUserDocsURL   = "https://github.com/sufield/stave/blob/main/docs/user-docs.md"
	CLIIssuesURL     = "https://github.com/sufield/stave/issues"
	CLIProjectConfig = "stave.yaml"
	CLILockfile      = "stave.lock"
)

// DocsRef returns a documentation reference for the given topic.
// If STAVE_DOCS_URL is set, it returns a URL with the topic as fragment.
// Otherwise it returns a local command reference.
func DocsRef(topic string) string {
	if topic == "" {
		topic = "troubleshooting"
	}
	if base := strings.TrimSpace(os.Getenv(envvar.DocsURL.Name)); base != "" {
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
