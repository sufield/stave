package contracts

import (
	"context"
	"errors"
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestOutputFormat_String(t *testing.T) {
	if FormatJSON.String() != "json" {
		t.Errorf("FormatJSON.String() = %q", FormatJSON.String())
	}
	if FormatText.String() != "text" {
		t.Errorf("FormatText.String() = %q", FormatText.String())
	}
}

func TestOutputFormat_IsJSON(t *testing.T) {
	if !FormatJSON.IsJSON() {
		t.Error("FormatJSON.IsJSON() should be true")
	}
	if FormatText.IsJSON() {
		t.Error("FormatText.IsJSON() should be false")
	}
}

// --- LoadControls / LoadSnapshots wrappers ---

type stubCtlRepo struct {
	controls []policy.ControlDefinition
	err      error
}

func (s stubCtlRepo) LoadControls(_ context.Context, _ string) ([]policy.ControlDefinition, error) {
	return s.controls, s.err
}

type stubObsRepo struct {
	result LoadResult
	err    error
}

func (s stubObsRepo) LoadSnapshots(_ context.Context, _ string) (LoadResult, error) {
	return s.result, s.err
}

func TestLoadControls_Success(t *testing.T) {
	repo := stubCtlRepo{controls: []policy.ControlDefinition{{ID: "CTL.A"}}}
	result, err := LoadControls(context.Background(), repo, "/ctl")
	if err != nil {
		t.Fatalf("LoadControls() error = %v", err)
	}
	if len(result) != 1 || result[0].ID != "CTL.A" {
		t.Errorf("result = %v", result)
	}
}

func TestLoadControls_Error(t *testing.T) {
	repo := stubCtlRepo{err: errors.New("boom")}
	_, err := LoadControls(context.Background(), repo, "/ctl")
	if err == nil || !strings.Contains(err.Error(), "failed to load controls") {
		t.Fatalf("expected wrapped error, got: %v", err)
	}
}

func TestLoadSnapshots_Success(t *testing.T) {
	repo := stubObsRepo{result: LoadResult{}}
	_, err := LoadSnapshots(context.Background(), repo, "/obs")
	if err != nil {
		t.Fatalf("LoadSnapshots() error = %v", err)
	}
}

func TestLoadSnapshots_Error(t *testing.T) {
	repo := stubObsRepo{err: errors.New("boom")}
	_, err := LoadSnapshots(context.Background(), repo, "/obs")
	if err == nil || !strings.Contains(err.Error(), "failed to load observations") {
		t.Fatalf("expected wrapped error, got: %v", err)
	}
}
