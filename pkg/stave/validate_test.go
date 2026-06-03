package stave_test

import (
	"context"
	"testing"

	"github.com/sufield/stave/pkg/stave"
)

func TestValidate_RequiresSnapshotsDir(t *testing.T) {
	_, err := stave.Validate(context.Background(), stave.ValidateConfig{})
	if err == nil {
		t.Fatal("expected error for empty SnapshotsDir")
	}
}

func TestValidate_BuiltinCatalog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	result, err := stave.Validate(context.Background(), stave.ValidateConfig{
		SnapshotsDir: "../../testdata/e2e/e2e-s3-golden-path/observations",
	})
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if result.ControlsChecked == 0 {
		t.Error("expected controls to be checked")
	}
	if result.SnapshotsChecked == 0 {
		t.Error("expected snapshots to be checked")
	}
}
