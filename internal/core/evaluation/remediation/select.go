package remediation

import (
	"fmt"
	"slices"
	"strings"
)

// SelectFinding locates a finding by its canonical key (<control_id>@<asset_id>).
func SelectFinding(findings []Finding, needle string) (Finding, error) {
	for i := range findings {
		if FindingKey(&findings[i]) == needle {
			return findings[i], nil
		}
	}

	keys := make([]string, 0, len(findings))
	for i := range findings {
		keys = append(keys, FindingKey(&findings[i]))
	}
	slices.Sort(keys)

	return Finding{}, fmt.Errorf(
		"finding %q not found; available findings:\n  %s",
		needle,
		strings.Join(keys, "\n  "),
	)
}

// FindingKey returns the canonical string selector for a finding.
func FindingKey(f *Finding) string {
	return string(f.ControlID) + "@" + string(f.AssetID)
}
