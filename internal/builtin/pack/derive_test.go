package pack

import (
	"testing"

	ctl "github.com/sufield/stave/internal/adapters/controls/builtin"
)

func TestDeriveControlRefsMatchesIndex(t *testing.T) {
	t.Parallel()
	reg := testRegistry(t)
	indexRefs := reg.ControlRefs()

	derived, err := DeriveControlRefs(ctl.EmbeddedFS(), "embedded")
	if err != nil {
		t.Fatalf("DeriveControlRefs: %v", err)
	}

	// Every control in the index must exist in derived with matching summary.
	for id, indexRef := range indexRefs {
		derivedRef, ok := derived[id]
		if !ok {
			t.Errorf("control %s in index but not derived from embedded FS", id)
			continue
		}
		// Path may differ in prefix (index uses internal/controldata/embedded/,
		// derived uses embedded/ from the FS root). Normalize for comparison.
		indexPath := normalizeControlFSPath(indexRef.Path)
		derivedPath := normalizeControlFSPath(derivedRef.Path)
		if indexPath != derivedPath {
			t.Errorf("control %s path mismatch:\n  index:   %s\n  derived: %s", id, indexPath, derivedPath)
		}
		if indexRef.Summary != derivedRef.Summary {
			t.Errorf("control %s summary mismatch:\n  index:   %q\n  derived: %q", id, indexRef.Summary, derivedRef.Summary)
		}
	}

	// Every control derived must exist in the index.
	for id := range derived {
		if _, ok := indexRefs[id]; !ok {
			t.Errorf("control %s derived from embedded FS but not in index", id)
		}
	}
}
