package stave

import (
	"slices"
	"sort"
	"time"

	"github.com/sufield/stave/internal/core/sir"
)

// GraphExport is the cross-service relationship view of an
// [Assessment]. Where [PolicyExport] carries individual policy
// documents, GraphExport carries the relationships between assets
// the assessment observed plus the findings and chains projected
// as nodes that hang off the asset graph.
//
// External tools combine this with a [PolicyExport] to build a
// complete reasoning picture: PolicyExport gives the "what does
// this policy say" data, GraphExport gives the "what reaches what"
// data. Neo4j and similar visualisers consume Assets + Edges
// directly; SMT solvers consume Findings + Chains as conjectures
// to discharge against the asset graph.
//
// TransitiveReachability is non-empty when [ExportGraph] was
// called with [WithSIRDocument]. The SIR builder computes
// multi-hop sts:AssumeRole paths in IdentityFact.RoleChains; this
// field surfaces them in flat per-path form so Z3 reachability
// queries can read the same edges the projector already emits as
// can_assume(from, to) JSONL triples — without rebuilding the
// transitive closure from direct edges.
type GraphExport struct {
	Assets                 []AssetNode
	Edges                  []AssetEdge
	Findings               []FindingNode
	Chains                 []ChainNode
	TransitiveReachability []ReachabilityPath
}

// ReachabilityPath is one transitive role-assumption path the SIR
// builder traced from a principal to a final role. Every Hop is
// one (from, to) edge along the path; HopTypes mirrors the
// `sts:AssumeRole` / `lambda_exec` / `tag_mutation` labels the SIR
// emits. CrossAccountHop is true when any hop crosses an account
// boundary — useful for quickly filtering paths that involve
// external trust.
//
// Determinism: paths are emitted in (FromPrincipal, FinalRole)
// sort order, hop sequences in source order. Same SIR document
// produces byte-identical paths across runs.
type ReachabilityPath struct {
	FromPrincipal     string   `json:"from_principal"`
	FinalRole         string   `json:"final_role"`
	Hops              []string `json:"hops"`
	HopTypes          []string `json:"hop_types"`
	CrossAccountHop   bool     `json:"cross_account_hop,omitempty"`
	TransitiveLevel   string   `json:"transitive_level,omitempty"`
	TerminationReason string   `json:"termination_reason,omitempty"`
}

// AssetLifecycleInfo is the SIR-derived per-asset existence
// envelope. Provisioned and Decommissioned are the same booleans
// the projector emits as is_provisioned / is_decommissioned JSONL
// triples; FirstSeen / LastSeen mirror the snapshot timestamps
// the SIR builder captured.
//
// Distinct from FindingNode.Lifecycle (the per-finding unsafe
// envelope). This block describes the asset's existence boundary
// across the observation set; the finding block describes how
// long the asset has been in violation.
type AssetLifecycleInfo struct {
	Provisioned    bool      `json:"provisioned,omitempty"`
	Decommissioned bool      `json:"decommissioned,omitempty"`
	FirstSeen      time.Time `json:"first_seen,omitzero"`
	LastSeen       time.Time `json:"last_seen,omitzero"`
}

// AssetNode is one asset referenced by the assessment. Identity
// fields (ID, Type) are pulled from each Finding's metadata —
// AssetNode does not require a snapshot to construct, so consumers
// that only have an [Assessment] can still build a graph view.
//
// HasFinding is true when at least one finding fired on the asset;
// it is convenient for visualisers that want to highlight
// "exposed" assets without re-walking the Findings slice.
//
// Lifecycle is non-nil when [ExportGraph] was called with
// [WithSIRDocument] AND the SIR document carries an AssetFact for
// this asset whose Lifecycle envelope is populated. The fields
// mirror the AssetFact.Lifecycle SIR shape so a downstream Z3
// query asking "was this asset newly provisioned in the latest
// snapshot?" reads the booleans directly.
type AssetNode struct {
	ID         AssetID
	Type       AssetType
	HasFinding bool
	Lifecycle  *AssetLifecycleInfo `json:"lifecycle,omitempty"`
}

// FindingNode is the graph-projection of one [Finding]. The fields
// are the subset SMT consumers and visualisers reason over —
// reasoning trace and remediation prose are intentionally omitted;
// callers that need them go to the originating [Finding] via
// FindingID.
//
// Lifecycle carries the engine's exposure-window evidence —
// FirstUnsafeAt, LastSeenUnsafeAt, UnsafeDurationHours — so
// solver consumers reasoning about dwell time, recurrence, or
// SLA breach do not have to re-derive timestamps from the
// originating snapshots. Nil when the engine produced no
// lifecycle data for the finding (typically when only a single
// snapshot was loaded). The data mirrors what `--max-unsafe`
// compares against on the CLI side, so a Z3 query asking "has
// this asset been unsafe long enough to violate the SLA?" can
// read FindingNode.Lifecycle.UnsafeDurationHours directly.
type FindingNode struct {
	FindingID     FindingID
	ControlID     ControlID
	AssetID       AssetID
	Severity      Severity
	ExposureScore float64
	IsChainMember bool
	Lifecycle     *FindingLifecycle
}

// FindingLifecycle is the temporal envelope around a finding's
// unsafe state — the same data the engine surfaces internally
// via Evidence.FirstUnsafeAt / LastSeenUnsafeAt /
// UnsafeDurationHours. Pointer-typed on FindingNode so the
// JSON form omits the block entirely when no lifecycle data
// is available rather than emitting a zero-valued struct.
type FindingLifecycle struct {
	FirstUnsafeAt       time.Time `json:"first_unsafe_at,omitzero"`
	LastSeenUnsafeAt    time.Time `json:"last_seen_unsafe_at,omitzero"`
	UnsafeDurationHours float64   `json:"unsafe_duration_hours,omitempty"`
}

// ChainNode is the graph-projection of one [ChainFinding]. Members
// references the FindingIDs of the Findings that contributed to the
// chain's activation; ControlsFailing is held in addition because
// a chain can name a missing control that has no fired Finding.
type ChainNode struct {
	ChainID         ChainID
	Severity        Severity
	CompoundScore   float64
	ControlsFailing []ControlID
	Members         []FindingID
}

// ExportGraph projects an [Assessment] into the cross-service
// relationship view. Assets are derived from the (AssetID,
// AssetType) pairs referenced by Findings; Edges link findings to
// their assets ("finding_about") and chains to their member
// findings ("chain_member"). Composes with [ExportPolicies] —
// concatenate AssetRelationships from PolicyExport with Edges from
// GraphExport for the full edge set.
//
// Returns nil for a nil assessment so callers can chain through
// optional pipelines without nil-guarding.
//
// Variadic [GraphOption] arguments enrich the export with data
// not derivable from the [Assessment] alone. Existing zero-arg
// callers see byte-identical output to the pre-options shape;
// adopters who want transitive role chains and per-asset
// lifecycle pass [WithSIRDocument] using the SIR doc applycore
// already built for fact-id correlation.
func ExportGraph(assessment *Assessment, opts ...GraphOption) *GraphExport {
	if assessment == nil {
		return nil
	}

	out := &GraphExport{}
	assets := newAssetSet()
	out.Findings = make([]FindingNode, 0, len(assessment.Findings))

	for i := range assessment.Findings {
		f := &assessment.Findings[i]
		assets.record(f.AssetID, f.AssetType, true)
		out.Findings = append(out.Findings, FindingNode{
			FindingID:     f.FindingID,
			ControlID:     f.ControlID,
			AssetID:       f.AssetID,
			Severity:      f.Severity,
			ExposureScore: f.ExposureScore,
			IsChainMember: len(f.ChainMembership) > 0,
			Lifecycle:     buildLifecycle(f),
		})
		out.Edges = append(out.Edges, AssetEdge{
			FromAssetID:  string(f.FindingID),
			ToAssetID:    string(f.AssetID),
			Relationship: "finding_about",
		})
	}

	out.Chains = make([]ChainNode, 0, len(assessment.ChainFindings))
	for i := range assessment.ChainFindings {
		cf := &assessment.ChainFindings[i]
		members := chainMembersFromFindings(assessment.Findings, cf.ChainID)
		out.Chains = append(out.Chains, ChainNode{
			ChainID:         cf.ChainID,
			Severity:        cf.Severity,
			CompoundScore:   cf.CompoundScore,
			ControlsFailing: append([]ControlID(nil), cf.ControlsFailing...),
			Members:         members,
		})
		for _, fid := range members {
			out.Edges = append(out.Edges, AssetEdge{
				FromAssetID:  string(cf.ChainID),
				ToAssetID:    string(fid),
				Relationship: "chain_member",
			})
		}
	}

	out.Assets = assets.sorted()
	sortGraphEdges(out.Edges)

	// Apply options last so they see the fully built graph and can
	// hydrate Asset / TransitiveReachability fields without
	// fighting the populator above. Options ordering matters only
	// when multiple modifiers touch the same field; the supplied
	// [WithSIRDocument] is the single hydrator today.
	for _, opt := range opts {
		opt(out)
	}
	return out
}

// GraphOption mutates a freshly built [GraphExport] before it is
// returned. The variadic shape on [ExportGraph] preserves
// backward compatibility — zero-arg callers see the same output
// they always saw.
type GraphOption func(*GraphExport)

// WithSIRDocument hydrates the GraphExport with transitive role
// chains and per-asset lifecycle envelopes drawn from the SIR
// document the same applycore pass already built for fact-id
// correlation. This is plumbing, not new computation: the SIR
// builder already runs IdentityFact.RoleChains[] and
// AssetFact.Lifecycle; this option surfaces them through the
// public graph API instead of having every consumer rebuild the
// projection from raw observations.
//
// nil doc is a no-op. Idempotent — calling it twice with the same
// document produces the same output.
//
// Determinism: TransitiveReachability is sorted by
// (FromPrincipal, FinalRole). AssetNode.Lifecycle attachment
// follows the existing AssetNode order set above. Same
// (assessment, sir.Document) input produces byte-identical
// output across runs.
func WithSIRDocument(doc *sir.Document) GraphOption {
	return func(g *GraphExport) {
		if g == nil || doc == nil {
			return
		}
		hydrateGraphFromSIR(g, doc)
	}
}

// hydrateGraphFromSIR projects the SIR document's transitive
// role-chain hops and per-asset lifecycle envelopes into the
// supplied GraphExport. Reads only — does not recompute. The SIR
// builder is the single source of truth for both fields.
func hydrateGraphFromSIR(g *GraphExport, doc *sir.Document) {
	// Per-asset lifecycle: iterate AssetNodes (already sorted)
	// and look up each by ID in the SIR's AssetFact slice. Two
	// passes through a small slice rather than a map because
	// AssetFact slices are typically O(10s); the constant-factor
	// improvement isn't worth a map allocation per call.
	for i := range g.Assets {
		assetID := string(g.Assets[i].ID)
		for j := range doc.Assets {
			af := &doc.Assets[j]
			if af.ID != assetID {
				continue
			}
			if af.Lifecycle == nil {
				break
			}
			lc := af.Lifecycle
			// Skip the block when nothing's worth reporting —
			// the omitempty contract on the json tag relies on
			// nil here, not on a zero-valued struct.
			if !lc.Provisioned && !lc.Decommissioned &&
				lc.FirstSeen.IsZero() && lc.LastSeen.IsZero() {
				break
			}
			g.Assets[i].Lifecycle = &AssetLifecycleInfo{
				Provisioned:    lc.Provisioned,
				Decommissioned: lc.Decommissioned,
				FirstSeen:      lc.FirstSeen,
				LastSeen:       lc.LastSeen,
			}
			break
		}
	}

	// Transitive reachability: every IdentityFact's RoleChains is
	// one path from the principal to a final role. Hops are
	// already in source order; the path walker captures them
	// verbatim plus the per-path metadata (cross-account,
	// transitive-level, termination-reason).
	for i := range doc.Identities {
		id := &doc.Identities[i]
		for j := range id.RoleChains {
			ch := &id.RoleChains[j]
			hops := make([]string, 0, len(ch.Hops))
			hopTypes := make([]string, 0, len(ch.Hops))
			anyCrossAccount := false
			for k := range ch.Hops {
				h := &ch.Hops[k]
				hops = append(hops, h.To)
				hopTypes = append(hopTypes, h.HopType)
				if h.CrossAccount {
					anyCrossAccount = true
				}
			}
			g.TransitiveReachability = append(g.TransitiveReachability, ReachabilityPath{
				FromPrincipal:     id.PrincipalID,
				FinalRole:         ch.FinalRoleARN,
				Hops:              hops,
				HopTypes:          hopTypes,
				CrossAccountHop:   anyCrossAccount,
				TransitiveLevel:   ch.TransitiveLevel,
				TerminationReason: ch.TerminationReason,
			})
		}
	}

	sort.Slice(g.TransitiveReachability, func(i, j int) bool {
		a, b := &g.TransitiveReachability[i], &g.TransitiveReachability[j]
		if a.FromPrincipal != b.FromPrincipal {
			return a.FromPrincipal < b.FromPrincipal
		}
		return a.FinalRole < b.FinalRole
	})
}

// buildLifecycle materialises the per-finding lifecycle envelope
// when the finding carries historical context. Pointer-typed
// return so the FindingNode JSON form omits the block entirely
// rather than emitting a zero-valued struct that downstream
// solvers might mistake for "duration zero". The
// "is there anything to report?" question is delegated to
// [Finding.HasTemporalEvidence] — adding a new temporal field
// to the lifecycle envelope is a one-line change there, no
// builder edits required.
func buildLifecycle(f *Finding) *FindingLifecycle {
	if !f.HasTemporalEvidence() {
		return nil
	}
	return &FindingLifecycle{
		FirstUnsafeAt:       f.FirstUnsafeAt,
		LastSeenUnsafeAt:    f.LastSeenUnsafeAt,
		UnsafeDurationHours: f.UnsafeDurationHours,
	}
}

// chainMembersFromFindings collects the FindingIDs of findings that
// list the given chain in their ChainMembership. The lookup is
// O(N×M) over (findings × chains) but stays bounded — chain
// definitions are sparse and the runtime is dominated by snapshot
// IO upstream.
func chainMembersFromFindings(findings []Finding, chainID ChainID) []FindingID {
	var out []FindingID
	for i := range findings {
		f := &findings[i]
		for _, m := range f.ChainMembership {
			if m.ChainID == chainID {
				out = append(out, f.FindingID)
				break
			}
		}
	}
	slices.Sort(out)
	return out
}

// assetSet deduplicates AssetNodes keyed by AssetID. The first
// recording of an asset's Type wins — subsequent records with a
// different Type are ignored, which matches the assessment
// invariant that AssetID uniquely identifies an asset within a run.
type assetSet struct {
	byID map[AssetID]AssetNode
}

func newAssetSet() *assetSet {
	return &assetSet{byID: map[AssetID]AssetNode{}}
}

func (s *assetSet) record(id AssetID, kind AssetType, hasFinding bool) {
	existing, ok := s.byID[id]
	if !ok {
		s.byID[id] = AssetNode{ID: id, Type: kind, HasFinding: hasFinding}
		return
	}
	existing.HasFinding = existing.HasFinding || hasFinding
	s.byID[id] = existing
}

func (s *assetSet) sorted() []AssetNode {
	if len(s.byID) == 0 {
		return nil
	}
	out := make([]AssetNode, 0, len(s.byID))
	for _, n := range s.byID {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// sortGraphEdges keeps the Edges slice in deterministic order so
// consumers diffing exports across runs see stable output.
func sortGraphEdges(edges []AssetEdge) {
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Relationship != edges[j].Relationship {
			return edges[i].Relationship < edges[j].Relationship
		}
		if edges[i].FromAssetID != edges[j].FromAssetID {
			return edges[i].FromAssetID < edges[j].FromAssetID
		}
		return edges[i].ToAssetID < edges[j].ToAssetID
	})
}
