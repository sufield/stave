package stave

import (
	"bytes"
	"context"
	"testing"
)

// TestRenderCatalogSearch_Formats exercises the rendering that moved here
// from cmd/search against the embedded catalog (empty dirs → builtin
// controls, no chains). Both formats must produce output for a query that
// matches at least one capability.
func TestRenderCatalogSearch_Formats(t *testing.T) {
	for _, format := range []string{"json", "text", ""} {
		out, err := RenderCatalogSearch(context.Background(), "s3 bucket", 10, "", "", format)
		if err != nil {
			t.Fatalf("RenderCatalogSearch(%q): unexpected error: %v", format, err)
		}
		if len(out) == 0 {
			t.Errorf("RenderCatalogSearch(%q): produced empty output", format)
		}
	}
}

func TestRenderSearchText_NoMatches(t *testing.T) {
	var buf bytes.Buffer
	renderSearchText(&buf, "zzz-no-such-thing", nil)
	if !bytes.Contains(buf.Bytes(), []byte("No matches")) {
		t.Errorf("zero-hit text should report no matches, got: %q", buf.String())
	}
}
