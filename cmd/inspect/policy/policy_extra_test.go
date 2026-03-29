package policy

import (
	"strings"
	"testing"
)

func TestReadInput_Stdin(t *testing.T) {
	r := strings.NewReader(`{"Version":"2012-10-17","Statement":[]}`)
	data, err := readInput("", r)
	if err != nil {
		t.Fatalf("readInput error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty data")
	}
}

func TestReadInput_MissingFile(t *testing.T) {
	_, err := readInput("/nonexistent/file.json", nil)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
