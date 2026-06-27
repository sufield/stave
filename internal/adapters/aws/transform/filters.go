package transform

import (
	"embed"
	"fmt"
)

// filterFS holds the jq filters that map raw AWS CLI output to obs.v0.1 assets.
// They are the single source of truth for the snapshot→observation mappings
// (extracted from scripts/aws-snapshot.sh) and ship embedded in the binary so
// `stave transform` needs no external files.
//
//go:embed filters/*.jq
var filterFS embed.FS

// filterProgram returns the jq program for a named filter (e.g. "iam-roles").
func filterProgram(name string) (string, error) {
	b, err := filterFS.ReadFile("filters/" + name + ".jq")
	if err != nil {
		return "", fmt.Errorf("unknown transform filter %q: %w", name, err)
	}
	return string(b), nil
}
