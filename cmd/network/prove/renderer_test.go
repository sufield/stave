package prove

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/network"
)

func TestNewRenderer(t *testing.T) {
	tests := []struct {
		format  string
		wantErr bool
	}{
		{"json", false},
		{"text", false},
		{"", false},
		{"xml", true},
		{"yaml", true},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			r, err := NewRenderer(tt.format)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewRenderer(%q) err = %v, wantErr %v", tt.format, err, tt.wantErr)
			}
			if !tt.wantErr && r == nil {
				t.Fatal("expected non-nil renderer")
			}
		})
	}
}

func TestJSONRenderer_Render(t *testing.T) {
	r, err := NewRenderer("json")
	if err != nil {
		t.Fatalf("NewRenderer(json) failed: %v", err)
	}

	res := &network.ProofResult{
		Property:       "bastion-ssh",
		Result:         "UNSAT",
		Interpretation: "All SSH paths traverse bastion",
		SolveTimeMs:    12,
	}

	var buf bytes.Buffer
	if err := r.Render(&buf, res); err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	var decoded network.ProofResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if decoded.Property != res.Property || decoded.Result != res.Result {
		t.Errorf("decoded result = %+v, want %+v", decoded, res)
	}
}

func TestTextRenderer_Render_UNSAT(t *testing.T) {
	r, err := NewRenderer("text")
	if err != nil {
		t.Fatalf("NewRenderer(text) failed: %v", err)
	}

	res := &network.ProofResult{
		Property:        "bastion-ssh",
		Result:          "UNSAT",
		Interpretation:  "All SSH paths to production traverse a bastion host.",
		ProductionHosts: 5,
		BastionHosts:    2,
		SSHPaths:        3,
		SolveTimeMs:     42,
	}

	var buf bytes.Buffer
	if err := r.Render(&buf, res); err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Bastion SSH Routing Proof") {
		t.Errorf("expected title in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Production hosts: 5") || !strings.Contains(out, "Bastion hosts:    2") {
		t.Errorf("expected host counts in output, got:\n%s", out)
	}
	if !strings.Contains(out, "No violation exists.") {
		t.Errorf("expected 'No violation exists.' in output, got:\n%s", out)
	}
}

func TestTextRenderer_Render_SAT_SGExposure(t *testing.T) {
	r, err := NewRenderer("text")
	if err != nil {
		t.Fatalf("NewRenderer(text) failed: %v", err)
	}

	res := &network.ProofResult{
		Property: "bastion-ssh",
		Result:   "SAT",
		Counterexample: &network.Counterexample{
			Source:      "i-bad",
			Destination: "i-prod",
			Port:        22,
			PathType:    "sg-ref",
			Explanation: "Direct SSH access permitted",
			Remediation: "Remove ingress rule on sg-prod",
			SGExposure: &network.SecurityGroupIngressExposure{
				SecurityGroupID: "sg-prod",
				RuleSource:      "sg-bad",
			},
		},
	}

	var buf bytes.Buffer
	if err := r.Render(&buf, res); err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "VIOLATION FOUND") {
		t.Errorf("expected 'VIOLATION FOUND' in header, got:\n%s", out)
	}
	if !strings.Contains(out, "COUNTEREXAMPLE:") {
		t.Errorf("expected 'COUNTEREXAMPLE:' section, got:\n%s", out)
	}
	if !strings.Contains(out, "Rule SG:     sg-prod") || !strings.Contains(out, "Rule source: sg-bad") {
		t.Errorf("expected SG exposure details, got:\n%s", out)
	}
	if !strings.Contains(out, "Port:        22") {
		t.Errorf("expected Port 22, got:\n%s", out)
	}
	if !strings.Contains(out, "REMEDIATION:\n    Remove ingress rule on sg-prod") {
		t.Errorf("expected remediation, got:\n%s", out)
	}
}

func TestTextRenderer_Render_SAT_RoutePath(t *testing.T) {
	r, err := NewRenderer("text")
	if err != nil {
		t.Fatalf("NewRenderer(text) failed: %v", err)
	}

	res := &network.ProofResult{
		Property: "firewall-mandatory",
		Result:   "SAT",
		Counterexample: &network.Counterexample{
			Source:      "subnet-priv",
			Destination: "igw-01",
			PathType:    "direct-igw",
			Explanation: "Subnet routes direct to IGW",
			Remediation: "Route through firewall",
			RoutePath: &network.UnprotectedRoutePath{
				RouteTableID: "rt-priv",
				Destination:  "0.0.0.0/0",
			},
		},
	}

	var buf bytes.Buffer
	if err := r.Render(&buf, res); err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Route table: rt-priv") || !strings.Contains(out, "Destination: 0.0.0.0/0") {
		t.Errorf("expected RoutePath details, got:\n%s", out)
	}
	// For direct-igw with port 0, Port line should be omitted.
	if strings.Contains(out, "Port:") {
		t.Errorf("expected port to be omitted for direct-igw, got:\n%s", out)
	}
}

func TestTextRenderer_Render_EVIDENCE_GATED(t *testing.T) {
	r, err := NewRenderer("text")
	if err != nil {
		t.Fatalf("NewRenderer(text) failed: %v", err)
	}

	res := &network.ProofResult{
		Property: "transitive-egress",
		Result:   "EVIDENCE_GATED",
		Counterexample: &network.Counterexample{
			Source:      "i-isolated",
			Destination: "i-relay",
			Port:        0,
			PathType:    "gated-egress",
			Explanation: "Reaches TGW route without table snapshot",
			Remediation: "Provide TGW observation",
			RuleSG:      "sg-relay",
			RuleSource:  "sg-isolated",
		},
	}

	var buf bytes.Buffer
	if err := r.Render(&buf, res); err != nil {
		t.Fatalf("Render() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "EVIDENCE GATED") {
		t.Errorf("expected 'EVIDENCE GATED' in title, got:\n%s", out)
	}
	if !strings.Contains(out, "Port:        all") {
		t.Errorf("expected 'Port:        all' for port 0 non-direct-igw, got:\n%s", out)
	}
	if !strings.Contains(out, "Rule SG:     sg-relay") {
		t.Errorf("expected fallback Rule SG, got:\n%s", out)
	}
}

func Test_renderCounterexample_NilSafe(t *testing.T) {
	var buf bytes.Buffer
	renderCounterexample(&buf, "HEADER:", nil)
	if buf.Len() != 0 {
		t.Errorf("expected empty output for nil counterexample, got: %s", buf.String())
	}
}

func Test_formatTitle(t *testing.T) {
	tests := []struct {
		property string
		result   string
		want     string
	}{
		{"bastion-ssh", "UNSAT", "Bastion SSH Routing Proof"},
		{"bastion-ssh", "SAT", "Bastion SSH Routing Proof — VIOLATION FOUND"},
		{"transitive-egress", "EVIDENCE_GATED", "Transitive Internet Egress Proof — EVIDENCE GATED"},
		{"unknown-prop", "SAT", "unknown-prop — VIOLATION FOUND"},
	}

	for _, tt := range tests {
		t.Run(tt.property+"_"+tt.result, func(t *testing.T) {
			got := formatTitle(tt.property, tt.result)
			if got != tt.want {
				t.Errorf("formatTitle(%q, %q) = %q, want %q", tt.property, tt.result, got, tt.want)
			}
		})
	}
}

func Test_renderHeader(t *testing.T) {
	var buf bytes.Buffer
	renderHeader(&buf, "bastion-ssh", "SAT")
	out := buf.String()
	want := "═══════════════════════════════════════════\nBastion SSH Routing Proof — VIOLATION FOUND\n═══════════════════════════════════════════\n\n"
	if out != want {
		t.Errorf("renderHeader output mismatch:\ngot:\n%q\nwant:\n%q", out, want)
	}
}

func Test_renderScope(t *testing.T) {
	t.Run("nil result outputs nothing", func(t *testing.T) {
		var buf bytes.Buffer
		renderScope(&buf, nil)
		if buf.Len() != 0 {
			t.Errorf("expected empty output for nil result, got %q", buf.String())
		}
	})

	t.Run("renders bastion and generic scope", func(t *testing.T) {
		res := &network.ProofResult{
			ProductionHosts: 4,
			BastionHosts:    1,
			SSHPaths:        2,
			Scope: map[string]int{
				"private_subnets": 3,
			},
		}
		var buf bytes.Buffer
		renderScope(&buf, res)
		out := buf.String()
		if !strings.Contains(out, "Production hosts: 4\n") {
			t.Errorf("missing Production hosts in %q", out)
		}
		if !strings.Contains(out, "Bastion hosts:    1\n") {
			t.Errorf("missing Bastion hosts in %q", out)
		}
		if !strings.Contains(out, "SSH paths:        2\n") {
			t.Errorf("missing SSH paths in %q", out)
		}
		if !strings.Contains(out, "private_subnets: 3\n") {
			t.Errorf("missing private_subnets in %q", out)
		}
	})
}

func Test_renderUnsat(t *testing.T) {
	t.Run("nil result outputs nothing", func(t *testing.T) {
		var buf bytes.Buffer
		renderUnsat(&buf, nil)
		if buf.Len() != 0 {
			t.Errorf("expected empty output for nil result, got %q", buf.String())
		}
	})

	t.Run("renders UNSAT proof details", func(t *testing.T) {
		res := &network.ProofResult{
			Interpretation: "All paths safe",
			SolveTimeMs:    15,
		}
		var buf bytes.Buffer
		renderUnsat(&buf, res)
		out := buf.String()
		if !strings.Contains(out, "PROOF: All paths safe\n") {
			t.Errorf("missing PROOF line in %q", out)
		}
		if !strings.Contains(out, "Solver: graph-search (completed in 15ms)\n") {
			t.Errorf("missing Solver line in %q", out)
		}
		if !strings.Contains(out, "No violation exists.\n") {
			t.Errorf("missing 'No violation exists.' in %q", out)
		}
	})
}
