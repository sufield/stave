package app_test

import (
	"context"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appvalidation "github.com/sufield/stave/internal/app/validation"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// stubControlRepo always returns an error to trigger load failure.
type stubControlRepo struct{}

func (s stubControlRepo) LoadControls(_ context.Context, _ string) ([]policy.ControlDefinition, error) {
	return nil, &stubLoadError{msg: "no such directory"}
}

// stubObservationRepo always returns an error.
type stubObservationRepo struct{}

func (s stubObservationRepo) LoadSnapshots(_ context.Context, _ string) (appcontracts.LoadResult, error) {
	return appcontracts.LoadResult{}, &stubLoadError{msg: "no such directory"}
}

type stubLoadError struct{ msg string }

func (e *stubLoadError) Error() string { return e.msg }

func TestValidateEvidence_LoadFailure_IncludesPath(t *testing.T) {
	run := appvalidation.NewRun(stubObservationRepo{}, stubControlRepo{})
	cfg := appvalidation.Config{
		ControlsDir:       "/home/user/secret/controls",
		ObservationsDir:   "/home/user/secret/observations",
		MaxUnsafeDuration: 168 * time.Hour,
		SanitizePaths:     false,
	}

	_, err := run.Execute(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for load failure")
	}

	// Error message should include the directory path
	if !strings.Contains(err.Error(), "/home/user/secret/controls") {
		t.Errorf("expected controls path in error, got: %v", err)
	}
}

func TestValidateEvidence_LoadFailure_ReturnsError(t *testing.T) {
	run := appvalidation.NewRun(stubObservationRepo{}, stubControlRepo{})
	cfg := appvalidation.Config{
		ControlsDir:       "/home/user/secret/controls",
		ObservationsDir:   "/home/user/secret/observations",
		MaxUnsafeDuration: 168 * time.Hour,
		SanitizePaths:     true,
	}

	_, err := run.Execute(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for load failure")
	}

	// Load failures should be returned as errors, not diagnostics
	if !strings.Contains(err.Error(), "no such directory") {
		t.Errorf("expected underlying error in message, got: %v", err)
	}
}
