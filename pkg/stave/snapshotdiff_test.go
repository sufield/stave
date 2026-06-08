package stave

import (
	"bytes"
	"testing"

	"github.com/sufield/stave/internal/app/snapshotdiff"
)

// TestWriteSnapshotDiffText_NonEmpty exercises the human-readable
// snapshot-diff renderer that moved here from cmd/snapshotdiff. An empty
// diff still emits the header and a "No differences found." line.
func TestWriteSnapshotDiffText_NonEmpty(t *testing.T) {
	var buf bytes.Buffer
	writeSnapshotDiffText(&buf, &snapshotdiff.DiffResult{})
	if buf.Len() == 0 {
		t.Error("writeSnapshotDiffText produced empty output")
	}
}
