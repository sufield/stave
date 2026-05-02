package evaluation

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

// Issue consolidates findings on the same asset that share a root-cause
// signal (overlapping predicate-consumed observation fields, per
// docs/product/metrics.md § Metric 2). One underlying misconfiguration
// produces one Issue regardless of how many controls fire on it;
// MemberFindings preserves full per-control fidelity so downstream
// tooling can still reach every finding's evidence + remediation.
//
// Issues are a view layer. They do not alter detection and do not
// replace Findings — the report emits both findings[] (per-control
// emission) and issues[] (consolidated view).
type Issue struct {
	// IssueID is a stable hash over (asset, sorted shared keys,
	// headline control). The same Issue on the same asset across
	// runs produces the same ID.
	IssueID kernel.IssueID `json:"issue_id"`

	// AssetID is the asset the Issue is rooted on. Issues are
	// strictly per-asset.
	AssetID asset.ID `json:"asset_id"`

	// SharedKeys lists the observation-field paths the member
	// controls collectively consumed (post discriminator-exclusion
	// and parent-namespace expansion), sorted lexicographically.
	SharedKeys []kernel.ObservationKey `json:"shared_keys"`

	// HeadlineFindingID is the FindingID of the highest-scored
	// member — the finding that best represents the Issue in
	// single-line summaries.
	HeadlineFindingID kernel.FindingID `json:"headline_finding_id"`

	// MemberFindingIDs lists every member finding's FindingID,
	// sorted lexicographically. Consumers cross-reference findings[]
	// for full detail. Typed so consumers can compare directly with
	// Finding.FindingID values (e.g. via slices.Contains) without
	// string casts.
	MemberFindingIDs []kernel.FindingID `json:"member_finding_ids"`

	// ConsolidatedScore is the maximum ExposureScore across members,
	// not the sum — Issues should not inflate priority beyond what
	// any individual member warrants.
	ConsolidatedScore kernel.ExposureScore `json:"consolidated_score"`

	// ConsolidatedBlastRadius is the maximum blast multiplier across
	// members, preserving the shape of the most impactful member.
	ConsolidatedBlastRadius kernel.BlastRadius `json:"consolidated_blast_radius"`
}

// IsConsolidated reports whether the Issue groups multiple findings.
// Domain question: does this Issue consolidate more than one finding?
func (i Issue) IsConsolidated() bool {
	return len(i.MemberFindingIDs) > 1
}

// discriminatorKeys are never included in the root-cause key set.
// These are kind-type gate clauses that appear on nearly every
// predicate of a given asset type; including them would cause every
// co-asset finding to transitively merge into one Issue via
// union-find (the pathological all-collapse failure mode).
//
// If the catalog adds a new kind-discriminator namespace, extend this
// list. Future iteration may drive discrimination from control
// metadata instead of a hardcoded list.
var discriminatorKeys = map[string]struct{}{
	"storage.kind":      {},
	"compute.kind":      {},
	"identity.kind":     {},
	"cryptography.kind": {},
	"container.kind":    {},
	"backup.kind":       {},
}

// rootCauseKeys projects a finding's ReasoningTrace ObservationKeys
// into the dedup-key set used for Issue consolidation. See
// docs/product/metrics.md § Metric 2 for the refined rule.
//
// Rules:
//   - Exclude kind-discriminator keys (type gates).
//   - For each remaining key, include both the full key and its
//     parent namespace (all segments but the last), but only when
//     the parent has ≥2 segments — a 1-segment parent like "storage"
//     is too coarse and would cluster unrelated domains.
func rootCauseKeys(trace []MatchedClause) map[string]struct{} {
	out := make(map[string]struct{})
	for _, mc := range trace {
		key := mc.ObservationKey.String()
		if _, skip := discriminatorKeys[key]; skip {
			continue
		}
		out[key] = struct{}{}
		if parent := parentNamespace(key); parent != "" {
			out[parent] = struct{}{}
		}
	}
	return out
}

// parentNamespace returns the all-but-last path segment of key,
// or an empty string when the parent has fewer than 2 segments.
func parentNamespace(key string) string {
	parts := strings.Split(key, ".")
	if len(parts) < 3 {
		// Strict ≥2 segments on the parent — e.g. "storage.foo.bar"
		// yields "storage.foo"; "storage.foo" (parent "storage") is
		// excluded as too coarse.
		return ""
	}
	return strings.Join(parts[:len(parts)-1], ".")
}

// unionFind is a minimal disjoint-set used to cluster findings by
// transitive root-cause overlap.
type unionFind struct {
	parent []int
}

func newUnionFind(n int) *unionFind {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	return &unionFind{parent: p}
}

func (u *unionFind) find(x int) int {
	for u.parent[x] != x {
		u.parent[x] = u.parent[u.parent[x]] // path compression
		x = u.parent[x]
	}
	return x
}

func (u *unionFind) union(a, b int) {
	ra, rb := u.find(a), u.find(b)
	if ra == rb {
		return
	}
	u.parent[ra] = rb
}

// BuildIssues consolidates findings sharing a root-cause into Issues.
// Every finding emits as part of exactly one Issue: multi-finding
// Issues when clusters form, singleton Issues otherwise.
//
// The input findings are not modified. Output is sorted by
// ConsolidatedScore descending, deterministic tie-breakers on
// AssetID, IssueID.
func BuildIssues(findings []Finding) []Issue {
	if len(findings) == 0 {
		return nil
	}

	// Per-asset scoping: a separate union-find per asset. Indices
	// into this slice's per-asset group are the union-find nodes.
	byAsset := make(map[asset.ID][]int)
	for i := range findings {
		byAsset[findings[i].AssetID] = append(byAsset[findings[i].AssetID], i)
	}

	var issues []Issue
	for assetID, indices := range byAsset {
		issues = append(issues, clusterAsset(assetID, indices, findings)...)
	}

	slices.SortFunc(issues, func(a, b Issue) int {
		return cmp.Or(
			cmp.Compare(b.ConsolidatedScore, a.ConsolidatedScore),
			cmp.Compare(a.AssetID, b.AssetID),
			cmp.Compare(a.IssueID, b.IssueID),
		)
	})
	return issues
}

// clusterAsset runs union-find over findings on a single asset.
func clusterAsset(assetID asset.ID, indices []int, findings []Finding) []Issue {
	n := len(indices)
	uf := newUnionFind(n)

	// Pre-compute each finding's root-cause key set.
	keys := make([]map[string]struct{}, n)
	for i, idx := range indices {
		keys[i] = rootCauseKeys(findings[idx].ReasoningTrace)
	}

	// Pair-wise overlap union. O(n^2 * avgKeys) — acceptable at
	// fixture scale (~20 findings per asset max observed).
	for i := range n {
		for j := i + 1; j < n; j++ {
			if overlap(keys[i], keys[j]) {
				uf.union(i, j)
			}
		}
	}

	// Group by cluster root.
	clusters := make(map[int][]int)
	for i := range n {
		r := uf.find(i)
		clusters[r] = append(clusters[r], indices[i])
	}

	issues := make([]Issue, 0, len(clusters))
	for _, members := range clusters {
		issues = append(issues, buildIssue(assetID, members, findings))
	}
	return issues
}

func overlap(a, b map[string]struct{}) bool {
	// Probe the smaller set against the larger for efficiency.
	if len(b) < len(a) {
		a, b = b, a
	}
	for k := range a {
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}

// buildIssue constructs a single Issue from a cluster's member
// finding indices. Iterates the indices in stable order so the
// headline pick (max ExposureScore) is deterministic when scores
// tie. The earlier shape iterated in the cluster-build's traversal
// order, which depended on map iteration; ties broke arbitrarily
// across runs and IssueID flapped.
func buildIssue(assetID asset.ID, memberIndices []int, findings []Finding) Issue {
	// Sort by ExposureScore desc, then FindingID asc for tie-break.
	// The IssueID hashes the headline's ControlID, so a non-
	// deterministic headline pick produces a non-deterministic
	// IssueID; consumers that diffed assessments across runs saw
	// flapping issue lists.
	indices := slices.Clone(memberIndices)
	slices.SortFunc(indices, func(a, b int) int {
		fa := &findings[a]
		fb := &findings[b]
		if fa.ExposureScore != fb.ExposureScore {
			if fa.ExposureScore > fb.ExposureScore {
				return -1
			}
			return 1
		}
		return cmp.Compare(fa.FindingID, fb.FindingID)
	})

	// Collect member IDs + find the headline (already first after sort).
	memberIDs := make([]kernel.FindingID, 0, len(indices))
	sharedSet := make(map[string]struct{})
	var headlineIdx int
	var headlineScore kernel.ExposureScore
	var maxBlast kernel.BlastRadius
	for i, idx := range indices {
		f := &findings[idx]
		memberIDs = append(memberIDs, f.FindingID)
		for k := range rootCauseKeys(f.ReasoningTrace) {
			sharedSet[k] = struct{}{}
		}
		if i == 0 {
			headlineIdx = idx
			headlineScore = f.ExposureScore
		}
		if f.ScoreBreakdown != nil && f.ScoreBreakdown.BlastMultiplier > maxBlast {
			maxBlast = f.ScoreBreakdown.BlastMultiplier
		}
	}
	slices.Sort(memberIDs)
	sharedStrings := make([]string, 0, len(sharedSet))
	for k := range sharedSet {
		sharedStrings = append(sharedStrings, k)
	}
	slices.Sort(sharedStrings)
	shared := make([]kernel.ObservationKey, len(sharedStrings))
	for i, s := range sharedStrings {
		shared[i] = kernel.ObservationKey(s)
	}

	return Issue{
		IssueID:                 stableIssueID(assetID, sharedStrings, findings[headlineIdx].ControlID),
		AssetID:                 assetID,
		SharedKeys:              shared,
		HeadlineFindingID:       findings[headlineIdx].FindingID,
		MemberFindingIDs:        memberIDs,
		ConsolidatedScore:       headlineScore,
		ConsolidatedBlastRadius: maxBlast,
	}
}

// stableIssueID is a deterministic fingerprint for the Issue's
// (asset, shared-keys, headline-control) triple. Same inputs on
// different runs produce the same ID.
func stableIssueID(assetID asset.ID, sharedKeys []string, headlineControlID kernel.ControlID) kernel.IssueID {
	h := sha256.New()
	h.Write([]byte("issue:"))
	h.Write([]byte(assetID))
	h.Write([]byte(":"))
	for _, k := range sharedKeys {
		h.Write([]byte(k))
		h.Write([]byte(","))
	}
	h.Write([]byte(":"))
	h.Write([]byte(headlineControlID))
	return kernel.IssueID("sha256:" + hex.EncodeToString(h.Sum(nil))[:16])
}
