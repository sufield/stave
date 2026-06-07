package exposure

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// The toCaps / ToDomain conversion tests moved to pkg/stave alongside the
// logic (stave.InspectExposure); these cover the command's input read.

func TestReadInput_Stdin(t *testing.T) {
	r := strings.NewReader(`{"resources":[]}`)
	data, err := fsutil.ReadFileOrStdin("", r)
	if err != nil {
		t.Fatalf("readInput error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty data")
	}
}

func TestReadInput_MissingFile(t *testing.T) {
	_, err := fsutil.ReadFileOrStdin("/nonexistent/file.json", nil)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
