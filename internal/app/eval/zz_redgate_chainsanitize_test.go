package eval

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/findings"
)

// Test_RedGate_ChainSanitize asserts the CORRECT behavior: under
// --sanitize, Enrich must mask asset identifiers carried on
// report.ChainFindings (CompoundFinding.AssetID, ContributingAssets),
// just as it masks RiskSignals, TopExposures, and Metadata.ResolvedPaths.
//
// sanitizeResultSidecars (enrich.go:66) enumerates every other
// identifier-bearing sidecar but omits ChainFindings. ChainFindings is
// still carried into the sanitized output envelope
// (output/envelope.go:36) and projected to the DTO (dto/mapper.go:25),
// and no later stage sanitizes it. So when a chain fires under
// --sanitize, chain_findings[].asset_id and
// chain_findings[].contributing_assets leak the real ARNs that
// --sanitize is supposed to mask everywhere else.
//
// White-box, deterministic: build a report with one ChainFinding
// carrying a real ARN, run Enrich with the package stubSanitizer
// (ID() prefixes "ID:"), and require the enriched copy's ChainFinding
// AssetID to be the ID:-prefixed token. Fails against current code
// because ChainFindings is never sanitized.
func Test_RedGate_ChainSanitize(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic during chain-finding sanitization: %v", r)
		}
	}()

	enricher := &stubEnricher{findings: nil}
	res := &evaluation.ComplianceReport{
		ChainFindings: []findings.CompoundFinding{
			{
				AssetID: asset.ID("arn:aws:s3:::secret"),
				ContributingAssets: []asset.ID{
					asset.ID("arn:aws:s3:::secret"),
					asset.ID("arn:aws:iam::123:role/admin"),
				},
			},
		},
	}

	enriched, err := Enrich(enricher, stubSanitizer{}, res)
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(enriched.Result.ChainFindings) != 1 {
		t.Fatalf("expected 1 chain finding, got %d", len(enriched.Result.ChainFindings))
	}

	cf := enriched.Result.ChainFindings[0]

	// CORRECT behavior: the chain finding's representative asset ID is
	// masked through the sanitizer (stubSanitizer.ID prefixes "ID:").
	// Current code leaves it as the raw ARN, so this goes RED.
	if got := string(cf.AssetID); got != "ID:arn:aws:s3:::secret" {
		t.Fatalf("ChainFinding AssetID = %q, want %q (--sanitize must mask chain_findings identifiers, not leak the real ARN)",
			got, "ID:arn:aws:s3:::secret")
	}

	// And every contributing asset ID must be masked too.
	wantContrib := []string{"ID:arn:aws:s3:::secret", "ID:arn:aws:iam::123:role/admin"}
	if len(cf.ContributingAssets) != len(wantContrib) {
		t.Fatalf("ContributingAssets len = %d, want %d", len(cf.ContributingAssets), len(wantContrib))
	}
	for i, want := range wantContrib {
		if got := string(cf.ContributingAssets[i]); got != want {
			t.Fatalf("ContributingAssets[%d] = %q, want %q (must be masked under --sanitize)", i, got, want)
		}
	}
}
