package prove

import (
	"bytes"
	"encoding/json"
	"slices"
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

func TestFormatTitle(t *testing.T) {
	tests := []struct {
		name     string
		property string
		result   string
		want     string
	}{
		{"empty property", "", "SAT", ""},
		{"bastion-ssh UNSAT", "bastion-ssh", "UNSAT", "Bastion SSH Routing Proof"},
		{"bastion-ssh SAT", "bastion-ssh", "SAT", "Bastion SSH Routing Proof — VIOLATION FOUND"},
		{"transitive-egress EVIDENCE_GATED", "transitive-egress", "EVIDENCE_GATED", "Transitive Internet Egress Proof — EVIDENCE GATED"},
		{"unknown-prop SAT", "unknown-prop", "SAT", "unknown-prop — VIOLATION FOUND"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatTitle(tt.property, tt.result)
			if got != tt.want {
				t.Errorf("FormatTitle(%q, %q) = %q, want %q", tt.property, tt.result, got, tt.want)
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

func Test_renderBastionScope(t *testing.T) {
	t.Run("nil result writes nothing", func(t *testing.T) {
		var buf bytes.Buffer
		renderBastionScope(&buf, nil)
		if buf.Len() != 0 {
			t.Errorf("expected empty output for nil result, got %q", buf.String())
		}
	})

	t.Run("zero counts write nothing", func(t *testing.T) {
		var buf bytes.Buffer
		renderBastionScope(&buf, &network.ProofResult{})
		if buf.Len() != 0 {
			t.Errorf("expected empty output for zero counts, got %q", buf.String())
		}
	})

	t.Run("renders present counts", func(t *testing.T) {
		var buf bytes.Buffer
		renderBastionScope(&buf, &network.ProofResult{
			ProductionHosts: 5,
			BastionHosts:    2,
			SSHPaths:        3,
		})
		out := buf.String()
		if !strings.Contains(out, "Production hosts: 5\n") || !strings.Contains(out, "Bastion hosts:    2\n") || !strings.Contains(out, "SSH paths:        3\n") {
			t.Errorf("unexpected renderBastionScope output: %q", out)
		}
	})
}

func Test_sortedScopeKeys(t *testing.T) {
	if got := sortedScopeKeys(nil); got != nil {
		t.Errorf("sortedScopeKeys(nil) = %v, want nil", got)
	}
	if got := sortedScopeKeys(map[string]int{}); got != nil {
		t.Errorf("sortedScopeKeys(empty) = %v, want nil", got)
	}

	scope := map[string]int{
		"zebra":  1,
		"apple":  2,
		"banana": 3,
	}
	got := sortedScopeKeys(scope)
	want := []string{"apple", "banana", "zebra"}
	if !slices.Equal(got, want) {
		t.Errorf("sortedScopeKeys() = %v, want %v", got, want)
	}
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

func Test_renderProofSummary(t *testing.T) {
	t.Run("nil result outputs nothing", func(t *testing.T) {
		var buf bytes.Buffer
		renderProofSummary(&buf, nil)
		if buf.Len() != 0 {
			t.Errorf("expected empty output for nil result, got %q", buf.String())
		}
	})

	t.Run("renders header and scope", func(t *testing.T) {
		res := &network.ProofResult{
			Property:        "bastion-ssh",
			Result:          "UNSAT",
			ProductionHosts: 3,
		}
		var buf bytes.Buffer
		renderProofSummary(&buf, res)
		out := buf.String()
		if !strings.Contains(out, "Bastion SSH Routing Proof") {
			t.Errorf("missing header in %q", out)
		}
		if !strings.Contains(out, "Production hosts: 3\n") {
			t.Errorf("missing scope in %q", out)
		}
	})
}

func Test_renderVerdict(t *testing.T) {
	t.Run("nil result outputs nothing", func(t *testing.T) {
		var buf bytes.Buffer
		renderVerdict(&buf, nil)
		if buf.Len() != 0 {
			t.Errorf("expected empty output for nil result, got %q", buf.String())
		}
	})

	t.Run("renders UNSAT verdict", func(t *testing.T) {
		res := &network.ProofResult{
			Result:         "UNSAT",
			Interpretation: "All paths safe",
		}
		var buf bytes.Buffer
		renderVerdict(&buf, res)
		if !strings.Contains(buf.String(), "No violation exists.") {
			t.Errorf("expected UNSAT verdict text, got %q", buf.String())
		}
	})

	t.Run("renders EVIDENCE_GATED verdict", func(t *testing.T) {
		res := &network.ProofResult{
			Result: "EVIDENCE_GATED",
			Counterexample: &network.Counterexample{
				Source:      "i-src",
				Destination: "i-dst",
			},
		}
		var buf bytes.Buffer
		renderVerdict(&buf, res)
		if !strings.Contains(buf.String(), "EVIDENCE GATED:") {
			t.Errorf("expected EVIDENCE GATED header, got %q", buf.String())
		}
	})

	t.Run("renders SAT verdict with counterexample", func(t *testing.T) {
		res := &network.ProofResult{
			Result: "SAT",
			Counterexample: &network.Counterexample{
				Source:      "i-src",
				Destination: "i-dst",
			},
		}
		var buf bytes.Buffer
		renderVerdict(&buf, res)
		if !strings.Contains(buf.String(), "COUNTEREXAMPLE:") {
			t.Errorf("expected COUNTEREXAMPLE header, got %q", buf.String())
		}
	})
}

func Test_renderCounterexamplePath(t *testing.T) {
	t.Run("nil counterexample outputs nothing", func(t *testing.T) {
		var buf bytes.Buffer
		renderCounterexamplePath(&buf, nil)
		if buf.Len() != 0 {
			t.Errorf("expected empty output for nil counterexample, got %q", buf.String())
		}
	})

	t.Run("renders source destination port and path", func(t *testing.T) {
		ce := &network.Counterexample{
			Source:      "i-app",
			Destination: "i-db",
			Port:        5432,
			PathType:    "sg-ref",
		}
		var buf bytes.Buffer
		renderCounterexamplePath(&buf, ce)
		out := buf.String()
		if !strings.Contains(out, "Source:      i-app") {
			t.Errorf("missing Source in %q", out)
		}
		if !strings.Contains(out, "Destination: i-db") {
			t.Errorf("missing Destination in %q", out)
		}
		if !strings.Contains(out, "Port:        5432") {
			t.Errorf("missing Port in %q", out)
		}
		if !strings.Contains(out, "Path:        sg-ref") {
			t.Errorf("missing Path in %q", out)
		}
	})
}

func Test_renderRemediation(t *testing.T) {
	t.Run("nil counterexample outputs nothing", func(t *testing.T) {
		var buf bytes.Buffer
		renderRemediation(&buf, nil)
		if buf.Len() != 0 {
			t.Errorf("expected empty output for nil counterexample, got %q", buf.String())
		}
	})

	t.Run("renders explanation and remediation block", func(t *testing.T) {
		ce := &network.Counterexample{
			Explanation: "Host i-app can reach database i-db.",
			Remediation: "Remove ingress rule on sg-db.",
		}
		var buf bytes.Buffer
		renderRemediation(&buf, ce)
		out := buf.String()
		if !strings.Contains(out, "Host i-app can reach database i-db.") {
			t.Errorf("missing Explanation in %q", out)
		}
		if !strings.Contains(out, "REMEDIATION:") {
			t.Errorf("missing REMEDIATION header in %q", out)
		}
		if !strings.Contains(out, "Remove ingress rule on sg-db.") {
			t.Errorf("missing Remediation in %q", out)
		}
	})
}

func Test_renderRouteViolation(t *testing.T) {
	t.Run("nil path outputs nothing", func(t *testing.T) {
		var buf bytes.Buffer
		renderRouteViolation(&buf, nil)
		if buf.Len() != 0 {
			t.Errorf("expected empty output for nil route path, got %q", buf.String())
		}
	})

	t.Run("renders route table and destination", func(t *testing.T) {
		p := &network.UnprotectedRoutePath{
			RouteTableID: "rtb-public",
			Destination:  "0.0.0.0/0",
		}
		var buf bytes.Buffer
		renderRouteViolation(&buf, p)
		out := buf.String()
		if !strings.Contains(out, "Route table: rtb-public") {
			t.Errorf("missing Route table in %q", out)
		}
		if !strings.Contains(out, "Destination: 0.0.0.0/0") {
			t.Errorf("missing Destination in %q", out)
		}
	})
}

func Test_renderSGExposure(t *testing.T) {
	t.Run("nil counterexample outputs nothing", func(t *testing.T) {
		var buf bytes.Buffer
		renderSGExposure(&buf, nil)
		if buf.Len() != 0 {
			t.Errorf("expected empty output for nil counterexample, got %q", buf.String())
		}
	})

	t.Run("renders structured SGExposure fields", func(t *testing.T) {
		ce := &network.Counterexample{
			SGExposure: &network.SecurityGroupIngressExposure{
				SecurityGroupID: "sg-app",
				RuleSource:      "0.0.0.0/0",
			},
		}
		var buf bytes.Buffer
		renderSGExposure(&buf, ce)
		out := buf.String()
		if !strings.Contains(out, "Rule SG:     sg-app") {
			t.Errorf("missing Rule SG in %q", out)
		}
		if !strings.Contains(out, "Rule source: 0.0.0.0/0") {
			t.Errorf("missing Rule source in %q", out)
		}
	})

	t.Run("renders legacy RuleSG and RuleSource fields", func(t *testing.T) {
		ce := &network.Counterexample{
			RuleSG:     "sg-legacy",
			RuleSource: "10.0.0.0/8",
		}
		var buf bytes.Buffer
		renderSGExposure(&buf, ce)
		out := buf.String()
		if !strings.Contains(out, "Rule SG:     sg-legacy") {
			t.Errorf("missing Rule SG in %q", out)
		}
		if !strings.Contains(out, "Rule source: 10.0.0.0/8") {
			t.Errorf("missing Rule source in %q", out)
		}
	})
}

func Test_renderPort(t *testing.T) {
	t.Run("nil counterexample outputs nothing", func(t *testing.T) {
		var buf bytes.Buffer
		renderPort(&buf, nil)
		if buf.Len() != 0 {
			t.Errorf("expected empty output for nil counterexample, got %q", buf.String())
		}
	})

	t.Run("direct-igw path outputs nothing", func(t *testing.T) {
		ce := &network.Counterexample{
			PathType: "direct-igw",
			Port:     22,
		}
		var buf bytes.Buffer
		renderPort(&buf, ce)
		if buf.Len() != 0 {
			t.Errorf("expected empty output for direct-igw, got %q", buf.String())
		}
	})

	t.Run("renders formatted port for other path types", func(t *testing.T) {
		ce := &network.Counterexample{
			PathType: "cross-vpc",
			Port:     5432,
		}
		var buf bytes.Buffer
		renderPort(&buf, ce)
		out := buf.String()
		if !strings.Contains(out, "Port:        5432") {
			t.Errorf("expected formatted port in output, got %q", out)
		}
	})
}

func TestPropertyTitle(t *testing.T) {
	t.Run("returns mapped title for known property", func(t *testing.T) {
		if title := PropertyTitle("bastion-ssh"); title != "Bastion SSH Routing Proof" {
			t.Errorf("PropertyTitle(bastion-ssh) = %q, want Bastion SSH Routing Proof", title)
		}
	})

	t.Run("returns property key for unknown property", func(t *testing.T) {
		if title := PropertyTitle("custom-prop"); title != "custom-prop" {
			t.Errorf("PropertyTitle(custom-prop) = %q, want custom-prop", title)
		}
	})
}

func Test_renderGenericScope(t *testing.T) {
	t.Run("empty scope outputs nothing", func(t *testing.T) {
		var buf bytes.Buffer
		renderGenericScope(&buf, nil)
		if buf.Len() != 0 {
			t.Errorf("expected empty output, got %q", buf.String())
		}
	})

	t.Run("renders sorted scope keys deterministically", func(t *testing.T) {
		scope := map[string]int{
			"zebra_hosts": 10,
			"alpha_hosts": 2,
			"beta_hosts":  5,
		}
		var buf bytes.Buffer
		renderGenericScope(&buf, scope)
		lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
		expected := []string{
			"  alpha_hosts: 2",
			"  beta_hosts: 5",
			"  zebra_hosts: 10",
		}
		if len(lines) != len(expected) {
			t.Fatalf("got %d lines, want %d", len(lines), len(expected))
		}
		for i, exp := range expected {
			if lines[i] != exp {
				t.Errorf("line %d = %q, want %q", i, lines[i], exp)
			}
		}
	})
}

func TestFormatSolverCompletion(t *testing.T) {
	got := FormatSolverCompletion(42)
	want := "Solver: graph-search (completed in 42ms)"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFormatUnsatProofBanner(t *testing.T) {
	got := FormatUnsatProofBanner("All paths are secure")
	want := "PROOF: All paths are secure"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func Test_verdictCounterexampleHeader(t *testing.T) {
	t.Run("nil result", func(t *testing.T) {
		if got := verdictCounterexampleHeader(nil); got != "" {
			t.Errorf("got %q, want empty string", got)
		}
	})

	t.Run("gated result", func(t *testing.T) {
		r := &network.ProofResult{Result: "EVIDENCE_GATED"}
		if got := verdictCounterexampleHeader(r); got != "EVIDENCE GATED:" {
			t.Errorf("got %q, want EVIDENCE GATED:", got)
		}
	})

	t.Run("SAT or other result", func(t *testing.T) {
		r := &network.ProofResult{Result: "SAT"}
		if got := verdictCounterexampleHeader(r); got != "COUNTEREXAMPLE:" {
			t.Errorf("got %q, want COUNTEREXAMPLE:", got)
		}
	})
}
