package exportinvariants

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestRun_EmitsBuiltinCatalogAsJSON verifies the happy path:
// no --controls means "use the built-in catalog", and the JSON
// document carries the invariants array with non-empty IDs.
func TestRun_EmitsBuiltinCatalogAsJSON(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := run(context.Background(), &buf, &options{Format: "json"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	var doc struct {
		Invariants []struct {
			ID             string `json:"id"`
			ForbiddenState struct {
				Combine string `json:"combine,omitempty"`
			} `json:"forbidden_state"`
		} `json:"invariants"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Invariants) == 0 {
		t.Fatal("expected non-empty invariants from built-in catalog")
	}
	for i, inv := range doc.Invariants {
		if inv.ID == "" {
			t.Errorf("invariant[%d] has empty id", i)
		}
	}
}

// TestRun_ReferenceControlCarriesForbiddenState confirms the
// reference invariant CTL.S3.ACCESS.EXTERNAL.ORG.001 surfaces
// the forbidden_state block on the JSON wire — the field the
// downstream Z3 compiler reads.
func TestRun_ReferenceControlCarriesForbiddenState(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := run(context.Background(), &buf, &options{Format: "json"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(buf.String(), `"id": "CTL.S3.ACCESS.EXTERNAL.ORG.001"`) {
		t.Fatal("reference control absent from output")
	}
	if !strings.Contains(buf.String(), `"forbidden_state":`) {
		t.Fatal("forbidden_state field absent from output")
	}
}

// TestRun_RejectsUnknownFormat guards the input-validation
// branch (exit code 2 in the CLI surface).
func TestRun_RejectsUnknownFormat(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	err := run(context.Background(), &buf, &options{Format: "yaml"})
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "--format must be json") {
		t.Errorf("error should explain format: got %q", err.Error())
	}
}
