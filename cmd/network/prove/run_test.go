package prove

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/network"
	"github.com/sufield/stave/pkg/stave"
)

type errRenderer struct{}

func (errRenderer) Render(_ io.Writer, _ *network.ProofResult) error {
	return errors.New("render failure")
}

func Test_executeAndRender_ValidationFailure(t *testing.T) {
	var buf bytes.Buffer
	r, err := NewRenderer("text")
	if err != nil {
		t.Fatalf("unexpected NewRenderer error: %v", err)
	}

	cfg := stave.NetworkProveConfig{SnapshotsDir: ""}
	err = executeAndRender(context.Background(), &buf, cfg, r)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "network prove:") {
		t.Errorf("unexpected error message: %v", err)
	}
}
