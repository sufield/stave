package eval

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

func Test_RedGate_IssueSanitize(t *testing.T) {
	enricher := &stubEnricher{findings: nil}
	res := &evaluation.ComplianceReport{
		Issues: []evaluation.Issue{
			{
				IssueID: kernel.IssueID("sha256:abc123"),
				AssetID: asset.ID("arn:aws:s3:::acme-customer-pii"),
			},
		},
	}

	enriched, err := Enrich(enricher, stubSanitizer{}, res)
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(enriched.Result.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(enriched.Result.Issues))
	}

	got := string(enriched.Result.Issues[0].AssetID)
	want := "ID:arn:aws:s3:::acme-customer-pii"
	if got != want {
		t.Fatalf("Issue.AssetID = %q, want %q (--sanitize must mask issues[].asset_id)", got, want)
	}
}
