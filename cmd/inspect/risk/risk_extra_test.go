package risk

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/platform/fsutil"
)

func TestReadInput_Stdin(t *testing.T) {
	r := strings.NewReader(`{"actions":["s3:GetObject"]}`)
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
