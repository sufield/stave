package attackpath

import (
	"bytes"
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBuild_MatchingCapability_ProducesEdge(t *testing.T) {
	chains := []policy.ChainDefinition{
		{
			ID:                  "chain_a",
			ControlIDs:          []kernel.ControlID{"CTL.A.001", "CTL.A.002"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityHigh,
			Postconditions:      []string{"iam_credential_theft"},
		},
		{
			ID:                  "chain_b",
			ControlIDs:          []kernel.ControlID{"CTL.B.001", "CTL.B.002"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityCritical,
			Preconditions:       []string{"iam_credential_theft"},
		},
	}
	findings := []ActiveFinding{
		{ChainID: kernel.ChainID("chain_a")},
		{ChainID: kernel.ChainID("chain_b")},
	}

	graph := Build(BuildInput{
		Chains:        chains,
		Findings:      findings,
		ControlLookup: map[string]*policy.ControlDefinition{},
	})

	if len(graph.Edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(graph.Edges))
	}
	edge := graph.Edges[0]
	if edge.FromChain != "chain_a" {
		t.Errorf("from_chain = %q, want chain_a", edge.FromChain)
	}
	if edge.ToChain != "chain_b" {
		t.Errorf("to_chain = %q, want chain_b", edge.ToChain)
	}
	if edge.ViaCapability != CapabilityID("iam_credential_theft") {
		t.Errorf("via_capability = %q, want iam_credential_theft", edge.ViaCapability)
	}
}

func TestBuild_NoMatch_ZeroEdges(t *testing.T) {
	chains := []policy.ChainDefinition{
		{
			ID:                  "chain_a",
			ControlIDs:          []kernel.ControlID{"CTL.A.001", "CTL.A.002"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityHigh,
			Postconditions:      []string{"internet_access"},
		},
		{
			ID:                  "chain_b",
			ControlIDs:          []kernel.ControlID{"CTL.B.001", "CTL.B.002"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityCritical,
			Preconditions:       []string{"iam_credential_theft"},
		},
	}
	findings := []ActiveFinding{
		{ChainID: kernel.ChainID("chain_a")},
		{ChainID: kernel.ChainID("chain_b")},
	}

	graph := Build(BuildInput{
		Chains:        chains,
		Findings:      findings,
		ControlLookup: map[string]*policy.ControlDefinition{},
	})

	if len(graph.Edges) != 0 {
		t.Errorf("expected 0 edges, got %d", len(graph.Edges))
	}
}

func TestBuild_InactiveChain_ExcludedFromEdges(t *testing.T) {
	chains := []policy.ChainDefinition{
		{
			ID:                  "chain_a",
			ControlIDs:          []kernel.ControlID{"CTL.A.001", "CTL.A.002"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityHigh,
			Postconditions:      []string{"iam_credential_theft"},
		},
		{
			ID:                  "chain_b",
			ControlIDs:          []kernel.ControlID{"CTL.B.001", "CTL.B.002"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityCritical,
			Preconditions:       []string{"iam_credential_theft"},
		},
	}
	// Only chain_a is active — chain_b is inactive.
	findings := []ActiveFinding{
		{ChainID: kernel.ChainID("chain_a")},
	}

	graph := Build(BuildInput{
		Chains:        chains,
		Findings:      findings,
		ControlLookup: map[string]*policy.ControlDefinition{},
	})

	if len(graph.Edges) != 0 {
		t.Errorf("expected 0 edges (chain_b inactive), got %d", len(graph.Edges))
	}

	// chain_b should still appear in nodes as inactive.
	found := false
	for _, n := range graph.ChainNodes {
		if n.ChainID == "chain_b" {
			found = true
			if n.Status != "inactive" {
				t.Errorf("chain_b status = %q, want inactive", n.Status)
			}
		}
	}
	if !found {
		t.Error("chain_b should appear in chain_nodes even when inactive")
	}
}

func TestBuild_UnannotatedChain_NoEdges(t *testing.T) {
	chains := []policy.ChainDefinition{
		{
			ID:                  "chain_no_caps",
			ControlIDs:          []kernel.ControlID{"CTL.A.001", "CTL.A.002"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityHigh,
			// No preconditions or postconditions.
		},
	}
	findings := []ActiveFinding{
		{ChainID: kernel.ChainID("chain_no_caps")},
	}

	graph := Build(BuildInput{
		Chains:        chains,
		Findings:      findings,
		ControlLookup: map[string]*policy.ControlDefinition{},
	})

	if len(graph.Edges) != 0 {
		t.Errorf("expected 0 edges for unannotated chain, got %d", len(graph.Edges))
	}
	if len(graph.ChainNodes) != 1 {
		t.Fatalf("expected 1 chain node, got %d", len(graph.ChainNodes))
	}
	if graph.ChainNodes[0].Status != "active" {
		t.Errorf("status = %q, want active", graph.ChainNodes[0].Status)
	}
}

func TestWriteDOT_ValidOutput(t *testing.T) {
	graph := &Graph{
		Capabilities: []Capability{
			{ID: CapabilityID("internet_access"), Label: "Internet Access"},
			{ID: CapabilityID("iam_credential_theft"), Label: "IAM Credentials"},
		},
		ChainNodes: []ChainNode{
			{
				ChainID:        "chain_a",
				Severity:       policy.SeverityHigh,
				Status:         "active",
				Preconditions:  []CapabilityID{"internet_access"},
				Postconditions: []CapabilityID{"iam_credential_theft"},
			},
		},
		Edges: []Edge{
			{
				FromChain:     "chain_a",
				ToChain:       "chain_b",
				ViaCapability: CapabilityID("iam_credential_theft"),
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteDOT(&buf, graph); err != nil {
		t.Fatalf("WriteDOT failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "digraph attack_paths") {
		t.Error("DOT output missing digraph header")
	}
	if !strings.Contains(out, "internet_access") {
		t.Error("DOT output missing capability node")
	}
	if !strings.Contains(out, "->") {
		t.Error("DOT output missing edge")
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "}") {
		t.Error("DOT output missing closing brace")
	}
}

func TestWriteCSVEdges(t *testing.T) {
	graph := &Graph{
		ChainNodes: []ChainNode{
			{ChainID: "chain_a", Severity: policy.SeverityHigh},
			{ChainID: "chain_b", Severity: policy.SeverityCritical},
		},
		Edges: []Edge{
			{
				FromChain:     "chain_a",
				ToChain:       "chain_b",
				ViaCapability: "iam_credential_theft",
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteCSVEdges(&buf, graph); err != nil {
		t.Fatalf("WriteCSVEdges failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (header + 1 edge), got %d", len(lines))
	}
	if !strings.HasPrefix(lines[0], "from_chain,") {
		t.Errorf("missing CSV header, got %q", lines[0])
	}
	if !strings.Contains(lines[1], "chain_a,chain_b,iam_credential_theft,high,critical") {
		t.Errorf("unexpected edge line: %q", lines[1])
	}
}

func TestAttackPath_DomainMethods(t *testing.T) {
	caps := Capabilities{
		{ID: CapabilityID("iam_credential_theft"), Label: "IAM Credentials"},
		{ID: CapabilityID("internet_access"), Label: "Internet Access"},
	}

	if caps.Len() != 2 {
		t.Errorf("caps.Len() = %d, want 2", caps.Len())
	}
	if caps.ByID(CapabilityID("iam_credential_theft")) == nil {
		t.Error("ByID(iam_credential_theft) should not be nil")
	}
	if caps.ByID(CapabilityID("nonexistent")) != nil {
		t.Error("ByID(nonexistent) should be nil")
	}

	nodes := ChainNodes{
		{ChainID: "chain_a", Status: "active"},
		{ChainID: "chain_b", Status: "inactive"},
		{ChainID: "chain_c", Status: "active"},
	}

	if nodes.Len() != 3 {
		t.Errorf("nodes.Len() = %d, want 3", nodes.Len())
	}

	active := nodes.Active()
	if active.Len() != 2 {
		t.Errorf("Active().Len() = %d, want 2", active.Len())
	}

	edges := Edges{
		{FromChain: "chain_a", ToChain: "chain_b"},
	}
	if edges.Len() != 1 {
		t.Errorf("edges.Len() = %d, want 1", edges.Len())
	}

	assets := AssetRefs{
		{AssetID: "asset-1"},
	}
	if assets.Len() != 1 {
		t.Errorf("assets.Len() = %d, want 1", assets.Len())
	}

	var emptyNodes ChainNodes
	if emptyNodes.Len() != 0 {
		t.Errorf("emptyNodes.Len() = %d, want 0", emptyNodes.Len())
	}
	if emptyNodes.Active() != nil {
		t.Error("emptyNodes.Active() should return nil")
	}
}

func TestCapabilityIDs_DomainMethods(t *testing.T) {
	ids := CapabilityIDs{"cap_a", "cap_b"}

	if ids.Len() != 2 {
		t.Errorf("Len: got %d, want 2", ids.Len())
	}
	if !ids.Contains("cap_a") {
		t.Error("Contains cap_a: got false, want true")
	}
	if ids.Contains("cap_c") {
		t.Error("Contains cap_c: got true, want false")
	}
}
