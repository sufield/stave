package stave

import (
	"slices"
	"sort"
	"time"
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
type GraphExport struct {
	Assets   []AssetNode
	Edges    []AssetEdge
	Findings []FindingNode
	Chains   []ChainNode
}

// AssetNode is one asset referenced by the assessment. Identity
// fields (ID, Type) are pulled from each Finding's metadata —
// AssetNode does not require a snapshot to construct, so consumers
// that only have an [Assessment] can still build a graph view.
//
// HasFinding is true when at least one finding fired on the asset;
// it is convenient for visualisers that want to highlight
// "exposed" assets without re-walking the Findings slice.
type AssetNode struct {
	ID         AssetID
	Type       AssetType
	HasFinding bool
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
func ExportGraph(assessment *Assessment) *GraphExport {
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
	return out
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
