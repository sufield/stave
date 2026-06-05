package sirfacts

import (
	"testing"

	"github.com/sufield/stave/internal/core/sir"
)

// Test_RedGate_ObsFloat is a RED-gate test for the bug at
// observation_facts.go:98 (appendObservationLeaves). Scalar leaf
// values are projected with fmt.Sprintf("%v", val). Because the
// observations loader uses plain json.Unmarshal (no UseNumber), a
// JSON integer like 31536000 lands in AssetFact.Properties as a
// float64, and fmt's default %v verb renders magnitudes >= 1e6 in
// scientific notation ("3.1536e+07"). The correct behavior is to
// emit the literal decimal digits "31536000" so a reasoning-engine
// query string-comparing against the literal value matches.
func Test_RedGate_ObsFloat(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()

	// Mirrors a JSON-loaded observation: numeric leaves arrive as
	// float64 after plain json.Unmarshal.
	assets := []sir.AssetFact{
		{
			ID:     "z1",
			Type:   "aws_cloudflare_zone",
			Vendor: "cloudflare",
			Properties: map[string]any{
				"tls": map[string]any{
					"hsts_max_age": float64(31536000),
				},
			},
		},
	}

	facts := ObservationFacts(assets)

	var got string
	found := false
	for _, f := range facts {
		if f.Subject == "z1" && f.Predicate == "tls.hsts_max_age" {
			got = f.Object
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no fact emitted for tls.hsts_max_age; facts=%+v", facts)
	}

	const want = "31536000"
	if got != want {
		t.Fatalf("integral float64 leaf rendered in scientific notation: Object = %q, want %q", got, want)
	}
}
