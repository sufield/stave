package asset

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/diag"
)

func TestValidateAllWarnsOnAmbiguousTagKeys(t *testing.T) {
	snapshots := Snapshots{
		{
			CapturedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			Resources: []Asset{
				{
					ID: "r-1",
					Properties: map[string]any{
						"storage": map[string]any{
							"tags": map[string]any{
								"Env": "prod",
								"env": "dev",
							},
						},
					},
				},
			},
		},
	}

	issues := snapshots.ValidateAll(time.Now().UTC(), 0)

	for _, issue := range issues {
		if issue.Code != diag.CodeAmbiguousTags {
			continue
		}
		gotResourceID, _ := issue.Evidence.Get("asset_id")
		if got := gotResourceID; got != "r-1" {
			t.Fatalf("asset_id evidence = %q, want r-1", got)
		}
		gotConflicts, _ := issue.Evidence.Get("conflict_keys")
		if got := gotConflicts; got != "env" {
			t.Fatalf("conflict_keys evidence = %q, want env", got)
		}
		return
	}

	t.Fatalf("expected %s issue, got: %v", diag.CodeAmbiguousTags, issues)
}
