package graph

import (
	"bytes"
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestWriteDOTChains_TwoActiveChains(t *testing.T) {
	active := []risk.CompoundFinding{
		{
			ChainID:         "root_compromise",
			ControlsFailing: []kernel.ControlID{"CTL.IAM.ROOT.MFA.001", "CTL.IAM.ROOT.ACCESSKEY.001"},
			CompoundScore:   45.0,
			Severity:        policy.SeverityCritical,
		},
		{
			ChainID:         "data_exfil",
			ControlsFailing: []kernel.ControlID{"CTL.EXPOSURE.EXFIL.001"},
			CompoundScore:   18.0,
			Severity:        policy.SeverityHigh,
		},
	}

	var buf bytes.Buffer
	if err := writeDOTChains(&buf, active, nil); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "digraph StaveChains") {
		t.Error("missing digraph header")
	}
	if !strings.Contains(out, "cluster_root_compromise") {
		t.Error("missing root_compromise cluster")
	}
	if !strings.Contains(out, "cluster_data_exfil") {
		t.Error("missing data_exfil cluster")
	}
	if !strings.Contains(out, "terminus_root_compromise") {
		t.Error("missing root_compromise terminus")
	}
	if !strings.Contains(out, "terminus_data_exfil") {
		t.Error("missing data_exfil terminus")
	}
	if !strings.Contains(out, "CTL.IAM.ROOT.MFA.001") {
		t.Error("missing control node")
	}
	if !strings.Contains(out, "#E24B4A") {
		t.Error("missing critical severity color")
	}
	if !strings.Contains(out, "#EF9F27") {
		t.Error("missing high severity color")
	}
}

func TestWriteDOTChains_InactiveNotRenderedByDefault(t *testing.T) {
	active := []risk.CompoundFinding{{
		ChainID:         "active_chain",
		ControlsFailing: []kernel.ControlID{"CTL.A"},
		CompoundScore:   10.0,
		Severity:        policy.SeverityHigh,
	}}

	var buf bytes.Buffer
	// nil inactive = no --all flag
	if err := writeDOTChains(&buf, active, nil); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "active_chain") {
		t.Error("missing active chain")
	}
	if strings.Contains(out, "(inactive)") {
		t.Error("inactive chains should not be rendered without --all")
	}
}

func TestWriteDOTChains_AllRendersInactive(t *testing.T) {
	active := []risk.CompoundFinding{{
		ChainID:         "active_chain",
		ControlsFailing: []kernel.ControlID{"CTL.A"},
		CompoundScore:   10.0,
		Severity:        policy.SeverityHigh,
	}}
	inactive := []policy.ChainDefinition{{
		ID:         "dormant_chain",
		ControlIDs: []kernel.ControlID{"CTL.X", "CTL.Y"},
	}}

	var buf bytes.Buffer
	if err := writeDOTChains(&buf, active, inactive); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "cluster_dormant_chain") {
		t.Error("missing inactive chain cluster")
	}
	if !strings.Contains(out, "(inactive)") {
		t.Error("inactive chain should be labeled as inactive")
	}
	if !strings.Contains(out, "dotted") {
		t.Error("inactive chain should use dotted style")
	}
	// Inactive chains should NOT have terminus nodes
	if strings.Contains(out, "terminus_dormant_chain") {
		t.Error("inactive chain should not have terminus node")
	}
}

func TestWriteDOTChains_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := writeDOTChains(&buf, nil, nil); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "digraph StaveChains") {
		t.Error("missing digraph header")
	}
	if !strings.Contains(out, "}") {
		t.Error("missing closing brace")
	}
}

func TestChainSlug(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"root-compromise-path", "root_compromise_path"},
		{"data.exfil", "data_exfil"},
		{"already_clean", "already_clean"},
	}
	for _, tt := range tests {
		if got := chainSlug(tt.input); got != tt.want {
			t.Errorf("chainSlug(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
