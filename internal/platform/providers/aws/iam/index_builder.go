package iam

import (
	"log/slog"
	"strings"

	"github.com/sufield/stave/internal/core/access"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/util/props"
)

// resourcePolicyPaths lists the property paths Stave's extractors
// emit a resource-based policy JSON document under. Centralised
// here so app code does not need to enumerate AWS-specific schema
// details.
var resourcePolicyPaths = [][]string{
	{"storage", "policy_json"},
	{"encryption", "key_policy_json"},
	{"compute", "resource_policy_json"},
	{"messaging", "policy_json"},
	{"secret", "resource_policy_json"},
}

// BuildResourceAccessIndex builds an access.ResourceAccessIndex
// from a snapshot's resource-based policies. Returns nil when the
// snapshot is empty or carries no IAM data, so callers can short-
// circuit annotation work.
//
// AWS-specific because policy JSON parsing and ARN account-ID
// extraction live with this provider.
func BuildResourceAccessIndex(snap *asset.Snapshot) *access.ResourceAccessIndex {
	if snap == nil || len(snap.Assets) == 0 {
		return nil
	}
	return BuildResourceAccessIndexFromSnapshots([]asset.Snapshot{*snap})
}

// BuildResourceAccessIndexFromSnapshots builds a merged
// ResourceAccessIndex from every snapshot in snaps. Multi-snapshot
// callers (apply against an observation history, watch loops) need
// the merged view so a finding's reachability annotation reflects
// every policy that has applied to the asset over time — building
// from `snapshots[0]` alone misses policies that landed in later
// captures.
//
// Returns nil when no snapshot in the slice carries IAM data.
func BuildResourceAccessIndexFromSnapshots(snaps []asset.Snapshot) *access.ResourceAccessIndex {
	if len(snaps) == 0 {
		return nil
	}

	// S3 bucket ARNs (arn:aws:s3:::bucket-name) lack account IDs.
	// Build per-snapshot account inference: when a snapshot contains
	// exactly one account, use it for S3 resources in that snapshot.
	// Per-snapshot inference (not merged) handles multi-account
	// observation sets where each snapshot captures one account.
	snapAccounts := make([]string, len(snaps))
	for s := range snaps {
		snap := &snaps[s]
		seen := make(map[string]struct{})
		for i := range snap.Assets {
			if acct := ExtractAccountID(string(snap.Assets[i].ID)); acct != "" {
				seen[acct] = struct{}{}
			}
		}
		if len(seen) == 1 {
			for a := range seen {
				snapAccounts[s] = a
			}
		}
	}

	idx := access.NewResourceAccessIndex()
	found := false
	for s := range snaps {
		snap := &snaps[s]
		if len(snap.Assets) == 0 {
			continue
		}
		for i := range snap.Assets {
			a := &snap.Assets[i]
			accountID := ExtractAccountID(string(a.ID))
			if accountID == "" && snapAccounts[s] != "" {
				accountID = snapAccounts[s]
			}
			for _, path := range resourcePolicyPaths {
				policyJSON := props.GetString(a.Properties, path)
				if policyJSON == "" {
					continue
				}
				found = true
				// AddResourcePolicy errors are non-fatal: malformed JSON
				// skips that policy but the asset observation is valid.
				// Log so operators can trace why an asset has no
				// reachability data — silent skips have masked extractor
				// bugs in the past.
				if addErr := AddResourcePolicy(idx, string(a.ID), policyJSON, accountID); addErr != nil {
					slog.Debug("aws/iam: skip resource policy annotation",
						"asset", a.ID, "path", strings.Join(path, "."), "err", addErr)
				}
			}
		}
	}
	if !found {
		return nil
	}
	return idx
}
