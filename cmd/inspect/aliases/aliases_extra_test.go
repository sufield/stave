package aliases

import (
	"bytes"
	"testing"
)

func TestRun_DefaultCategory(t *testing.T) {
	if err := run(Input{Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("run error: %v", err)
	}
}
