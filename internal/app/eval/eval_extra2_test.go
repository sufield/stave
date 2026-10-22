package eval

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/sanitize"
)

func TestEnrich_WithSanitizer(t *testing.T) {
	s := sanitize.New(sanitize.WithIDSanitization(true))
	enricher := remediation.NewPlanner()

	result := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			InputHashes: &evaluation.InputHashes{
				Files: map[evaluation.FilePath]kernel.Digest{
					"/tmp/a.json": "sha256:aaa",
				},
				Overall: "sha256:combined",
			},
			EvaluatedState: "deployed",
		},
		ExemptedAssets: []asset.ExemptedAsset{
			{ID: "bucket-secret", Pattern: "bucket-*", Reason: "temp"},
		},
	}

	enriched, err := Enrich(enricher, s, &result)
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if enriched.ExemptedAssets[0].ID == "bucket-secret" {
		t.Error("expected sanitized asset ID")
	}
	for path := range enriched.Run.InputHashes.Files {
		if strings.Contains(string(path), "/tmp/") {
			t.Error("expected sanitized path")
		}
	}
}
