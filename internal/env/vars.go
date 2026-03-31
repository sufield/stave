// Package env centralizes all STAVE_* environment variable names.
// Every Stave-specific env var should be referenced through this package
// so that renames are single-point and the full set is discoverable.
package env

import (
	"os"
	"slices"
	"strconv"
	"strings"
)

// Entry describes a single STAVE_* environment variable.
type Entry struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Category     string `json:"category"`
	DefaultValue string `json:"default_value,omitempty"`
}

// Value returns the effective value: the environment variable if set,
// otherwise DefaultValue.
func (e Entry) Value() string {
	if val := strings.TrimSpace(os.Getenv(e.Name)); val != "" {
		return val
	}
	return e.DefaultValue
}

// IsTrue returns true if the environment variable is set to a truthy value.
// It accepts all forms recognized by strconv.ParseBool: 1, t, T, TRUE, true,
// True, 0, f, F, FALSE, false, False. Unset or unparseable values are false.
func (e Entry) IsTrue() bool {
	v := strings.TrimSpace(os.Getenv(e.Name))
	b, err := strconv.ParseBool(v)
	return err == nil && b
}

// Configuration override env vars (user-facing).
var (
	CIFailurePolicy = Entry{
		Name:         "STAVE_CI_FAILURE_POLICY",
		Description:  "Override CI gate failure policy",
		Category:     "config",
		DefaultValue: "fail_on_any_violation",
	}
	Context = Entry{
		Name:        "STAVE_CONTEXT",
		Description: "Override active context name",
		Category:    "config",
	}
	ContextsFile = Entry{
		Name:        "STAVE_CONTEXTS_FILE",
		Description: "Path to contexts definition file",
		Category:    "config",
	}
	DocsURL = Entry{
		Name:        "STAVE_DOCS_URL",
		Description: "Override documentation base URL for hints and error messages",
		Category:    "config",
	}
	IssuesURL = Entry{
		Name:         "STAVE_ISSUES_URL",
		Description:  "Override issue tracker URL for bug reports and error messages",
		Category:     "config",
		DefaultValue: "https://github.com/sufield/stave/issues",
	}
	Demo = Entry{
		Name:        "STAVE_DEMO",
		Description: "Suppress hints, tips, and next-step suggestions for demo/tutorial output",
		Category:    "config",
	}
	FirstRunHintFile = Entry{
		Name:        "STAVE_FIRST_RUN_HINT_FILE",
		Description: "Override path to first-run hint marker file",
		Category:    "config",
	}
	MaxUnsafe = Entry{
		Name:         "STAVE_MAX_UNSAFE",
		Description:  "Override default max-unsafe duration threshold",
		Category:     "config",
		DefaultValue: "168h",
	}
	ProjectRoot = Entry{
		Name:        "STAVE_PROJECT_ROOT",
		Description: "Override project root directory for path inference",
		Category:    "config",
	}
	RetentionTier = Entry{
		Name:         "STAVE_RETENTION_TIER",
		Description:  "Override default retention tier",
		Category:     "config",
		DefaultValue: "critical",
	}
	SnapshotRetention = Entry{
		Name:         "STAVE_SNAPSHOT_RETENTION",
		Description:  "Override default snapshot retention period",
		Category:     "config",
		DefaultValue: "30d",
	}
	UserConfig = Entry{
		Name:        "STAVE_USER_CONFIG",
		Description: "Path to user-level CLI config file",
		Category:    "config",
	}
)

// Developer/debug env vars.
var (
	Debug = Entry{
		Name:        "STAVE_DEBUG",
		Description: "Enable debug output (set to 1)",
		Category:    "debug",
	}
	DevValidateFindings = Entry{
		Name:        "STAVE_DEV_VALIDATE_FINDINGS",
		Description: "Enable finding contract validation (set to 1 or true)",
		Category:    "debug",
	}
)

// all is the registry of every STAVE_* variable. Order does not matter here;
// All() sorts the result programmatically.
var all = []Entry{
	CIFailurePolicy,
	Context,
	ContextsFile,
	Debug,
	DevValidateFindings,
	DocsURL,
	Demo,
	FirstRunHintFile,
	IssuesURL,
	MaxUnsafe,
	ProjectRoot,
	RetentionTier,
	SnapshotRetention,
	UserConfig,
}

// All returns every registered STAVE_* variable in deterministic order:
// sorted by category then name. The returned slice is a fresh copy.
func All() []Entry {
	out := make([]Entry, len(all))
	copy(out, all)
	slices.SortFunc(out, func(a, b Entry) int {
		if c := strings.Compare(a.Category, b.Category); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}
