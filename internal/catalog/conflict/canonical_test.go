package conflict

import "testing"

// TestCanonicalCompliance_Golden pins the canonical-form contract for
// shared_compliance_hash. If this test fails, the canonicalization
// changed — every cached hash in downstream consumers is now invalid.
// Document the bump in the ontology CHANGELOG before updating the
// golden, never the other way around.
func TestCanonicalCompliance_Golden(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"empty", nil, ""},
		{"single", []string{"PCI-DSS:1.2"}, "PCI-DSS:1.2"},
		{"sorts", []string{"SOC2:CC6.1", "PCI-DSS:1.2"}, "PCI-DSS:1.2|SOC2:CC6.1"},
		{"dedups", []string{"SOC2:CC6.1", "PCI-DSS:1.2", "SOC2:CC6.1"}, "PCI-DSS:1.2|SOC2:CC6.1"},
		{"case-preserved", []string{"soc2:cc6.1", "SOC2:CC6.1"}, "SOC2:CC6.1|soc2:cc6.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CanonicalCompliance(c.in)
			if got != c.want {
				t.Errorf("CanonicalCompliance(%v) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestHashCompliance_Golden pins the SHA-256 output for a known
// compliance input. If this fails, either the canonicalization
// changed or the hash function changed — both are contract breaks.
func TestHashCompliance_Golden(t *testing.T) {
	got := HashSHA256(CanonicalCompliance([]string{"SOC2:CC6.1", "PCI-DSS:1.2"}))
	const want = "sha256:f49a294bded7d042be25e92979b2ef1be7fba9cfd119a2366f84b577efdd2920"
	if got == want {
		return // pin matched
	}
	// Compute and report the actual hash so the test author can update
	// the golden deliberately. Failing with the actual value is a
	// one-step recovery; failing with just "mismatch" leaves the
	// author re-running tests to discover the new value.
	t.Errorf("HashSHA256 of canonical compliance changed.\n  got:  %s\n  want: %s\n  → if this is intentional, bump the ontology CHANGELOG and update the golden",
		got, want)
}

func TestCanonicalRemediation_Golden(t *testing.T) {
	cases := []struct {
		name            string
		action, example string
		want            string
	}{
		{"both empty", "", "", "|"},
		{"action only", "Block public access", "", "Block public access|"},
		{"example only", "", "aws s3api put-public-access-block", "|aws s3api put-public-access-block"},
		{
			"whitespace collapsed",
			"  Block   public\taccess  ",
			"  aws s3api  put-public-access-block --bucket FOO  ",
			"Block public access|aws s3api put-public-access-block --bucket FOO",
		},
		{
			"newlines folded",
			"Line one\nLine two",
			"cmd \\\n  --flag",
			"Line one Line two|cmd \\ --flag",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CanonicalRemediation(c.action, c.example)
			if got != c.want {
				t.Errorf("CanonicalRemediation(%q, %q) = %q, want %q",
					c.action, c.example, got, c.want)
			}
		})
	}
}

func TestHashRemediation_Golden(t *testing.T) {
	got := HashSHA256(CanonicalRemediation(
		"Block public access",
		"aws s3api put-public-access-block --bucket FOO",
	))
	const want = "sha256:b4cb1cf368b1776d0566aa76f28a5244f59299436e8c73e5dfa78461ce5238bb"
	if got == want {
		return
	}
	t.Errorf("HashSHA256 of canonical remediation changed.\n  got:  %s\n  want: %s\n  → if intentional, bump the ontology CHANGELOG and update the golden",
		got, want)
}

func TestHashSHA256_PrefixAndLength(t *testing.T) {
	got := HashSHA256("anything")
	if len(got) != len("sha256:")+64 {
		t.Errorf("HashSHA256 length = %d, want 7+64", len(got))
	}
	if got[:7] != "sha256:" {
		t.Errorf("HashSHA256 prefix = %q, want sha256:", got[:7])
	}
}
