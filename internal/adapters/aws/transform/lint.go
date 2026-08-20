package transform

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/itchyny/gojq"
)

// lint.go supports the contributor workflow: it checks every embedded .jq filter
// compiles and emits the obs.v0.1 asset shape, and that the detect map and the
// filter files stay in sync. ScaffoldContent produces a starter filter.

// FilterIssue is one lint finding. Fatal issues mean a filter is broken (won't
// run); non-fatal issues are advisory (the filter may still work).
type FilterIssue struct {
	Filter  string `json:"filter"`
	Message string `json:"message"`
	Fatal   bool   `json:"fatal"`
}

// LintFilters checks all embedded filters and the detect-map ↔ files consistency.
// Returns the issues found (empty slice = clean).
func LintFilters() ([]FilterIssue, error) {
	entries, err := filterFS.ReadDir("filters")
	if err != nil {
		return nil, fmt.Errorf("read embedded filters: %w", err)
	}

	present := map[string]bool{}
	var issues []FilterIssue
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".jq")
		present[name] = true
		program, err := filterProgram(name)
		if err != nil {
			issues = append(issues, FilterIssue{Filter: name, Message: err.Error(), Fatal: true})
			continue
		}
		issues = append(issues, lintProgram(name, program)...)
	}

	// Every referenced filter must have a file...
	for _, ref := range referencedFilters() {
		if !present[ref] {
			issues = append(issues, FilterIssue{
				Filter:  ref,
				Message: "referenced by detect.go but no filters/" + ref + ".jq exists",
				Fatal:   true,
			})
		}
	}
	// ...and every file should be referenced (orphan check, advisory).
	referenced := map[string]bool{}
	for _, ref := range referencedFilters() {
		referenced[ref] = true
	}
	for name := range present {
		if !referenced[name] {
			issues = append(issues, FilterIssue{
				Filter:  name,
				Message: "filter file is not referenced in detect.go (orphan)",
				Fatal:   false,
			})
		}
	}

	slices.SortFunc(issues, func(a, b FilterIssue) int {
		if c := cmp.Compare(a.Filter, b.Filter); c != 0 {
			return c
		}
		return cmp.Compare(a.Message, b.Message)
	})
	return issues, nil
}

// lintProgram compiles one filter and applies structural heuristics for the
// obs.v0.1 asset shape. A compile error is fatal; a missing required field is
// advisory (the program may build it in a way the text scan can't see).
func lintProgram(name, program string) []FilterIssue {
	var issues []FilterIssue
	query, err := gojq.Parse(program)
	if err != nil {
		return []FilterIssue{{Filter: name, Message: "jq parse error: " + err.Error(), Fatal: true}}
	}
	if _, err := gojq.Compile(query, gojq.WithVariables([]string{"$account"})); err != nil {
		return []FilterIssue{{Filter: name, Message: "jq compile error: " + err.Error(), Fatal: true}}
	}
	for _, field := range []string{"id:", "type:", "vendor:", "properties:"} {
		if !strings.Contains(program, field) {
			issues = append(issues, FilterIssue{
				Filter:  name,
				Message: "output does not appear to set obs.v0.1 asset field " + strings.TrimSuffix(field, ":"),
				Fatal:   false,
			})
		}
	}
	return issues
}

// ScaffoldContent returns a starter .jq filter for a new resource type. name is
// the filter name (e.g. "kms-keys"); topLevelKey is the AWS CLI response key the
// filter consumes (e.g. "Keys").
func ScaffoldContent(name, topLevelKey string) string {
	if topLevelKey == "" {
		topLevelKey = "Items"
	}
	return fmt.Sprintf(`# %s.jq — convert raw AWS CLI output into obs.v0.1 assets.
# Emit one object per resource with the obs.v0.1 asset shape:
#   { id, type, vendor, properties }
# Then register the top-level key in topLevelKeyToFilter (detect.go):
#   "%s": "%s"
# and add a test against committed lab data (see docs/transform/CONTRIBUTING.md).
.%s[] | {
  id: .Arn,                       # ARN is the obs.v0.1 asset id convention
  type: "aws_REPLACE_resource",
  vendor: "aws",
  properties: {
    REPLACE_namespace: {
      kind: "REPLACE_kind"
      # map raw fields -> obs properties here
    }
  }
}
`, name, topLevelKey, name, topLevelKey)
}
