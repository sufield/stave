package iam

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

// ExtractScheduledDeletions scans every CloudIdentity in the
// snapshot and returns, per principal ARN, the timestamp at which
// the role / user is scheduled for deletion. Identities with no
// scheduled deletion are omitted from the result.
//
// Iter 5 (TOCTOU): the chain walker consults this map to mark
// chains whose target is scheduled for future deletion — the
// "future ghost reference" pattern from gap-prompt.md:9. A chain
// pointing at a role that will be deleted in 24 hours is unsafe
// even though it is observed-reachable now: any consumer that
// re-checks after the deletion window finds a hole.
//
// The extractor reads two property conventions, both already used
// elsewhere in Stave:
//   - identity.lifecycle.scheduled_for_deletion_at (RFC3339
//     timestamp, the canonical form for scheduled deletions on
//     IAM users / roles).
//   - identity.lifecycle.deletion_date (the form already used by
//     the secretsmanager extractor in
//     CTL.SECRETS.GHOST.DELETION.REFERENCED.001 — accepted here
//     so collectors can reuse the same key across resource types).
//
// Either key wins; the FIRST recognised value is returned. Both
// keys must parse as RFC3339 — malformed timestamps drop the
// identity from the map (fail-loud at parse time would be wrong
// here, since extractors should not crash the chain walker).
func ExtractScheduledDeletions(snap *asset.Snapshot) map[string]time.Time {
	if snap == nil {
		return nil
	}
	out := make(map[string]time.Time, len(snap.Identities))
	for i := range snap.Identities {
		id := &snap.Identities[i]
		ts := readDeletionTimestamp(id.Properties)
		if ts.IsZero() {
			continue
		}
		out[string(id.ID)] = ts
	}
	return out
}

// readDeletionTimestamp probes the two property keys Stave's
// collectors emit for "this resource is scheduled to be deleted
// at T". Order is significant: the canonical IAM key wins over
// the secretsmanager-shaped fallback so a future-divergence in
// the two conventions doesn't silently flip the source-of-truth.
func readDeletionTimestamp(props map[string]any) time.Time {
	for _, keyPath := range [][]string{
		{"identity", "lifecycle", "scheduled_for_deletion_at"},
		{"identity", "lifecycle", "deletion_date"},
	} {
		raw := stringProperty(props, keyPath...)
		if raw == "" {
			continue
		}
		ts, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			continue
		}
		return ts
	}
	return time.Time{}
}
