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

	snapAccounts := inferSnapAccounts(snaps)

	idx := access.NewResourceAccessIndex()
	found := false
	for s := range snaps {
		snap := &snaps[s]
		for i := range snap.Assets {
			if indexAssetResourcePolicies(idx, &snap.Assets[i], snapAccounts[s]) {
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	return idx
}

func indexAssetResourcePolicies(idx *access.ResourceAccessIndex, a *asset.Asset, snapAccount string) bool {
	accountID := ExtractAccountID(string(a.ID))
	if accountID == "" && snapAccount != "" {
		accountID = snapAccount
	}
	found := false
	for _, path := range resourcePolicyPaths {
		policyJSON := props.GetString(a.Properties, path)
		if policyJSON == "" {
			continue
		}
		found = true
		if addErr := AddResourcePolicy(idx, string(a.ID), policyJSON, accountID); addErr != nil {
			slog.Debug("aws/iam: skip resource policy annotation",
				"asset", a.ID, "path", strings.Join(path, "."), "err", addErr)
		}
	}
	return found
}

// inferSnapAccounts returns a per-snapshot account ID when a snapshot
// contains exactly one account. S3 bucket ARNs lack account IDs;
// per-snapshot inference fills the gap without merging across
// multi-account observation sets.
func inferSnapAccounts(snaps []asset.Snapshot) []string {
	accounts := make([]string, len(snaps))
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
				accounts[s] = a
			}
		}
	}
	return accounts
}
