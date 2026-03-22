package app_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appvalidation "github.com/sufield/stave/internal/app/validation"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// stubControlRepo always returns an error to trigger evidence creation.
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

func TestValidateEvidence_RedactPaths_False(t *testing.T) {
	run := appvalidation.NewRun(stubObservationRepo{}, stubControlRepo{})
	cfg := appvalidation.Config{
		ControlsDir:       "/home/user/secret/controls",
		ObservationsDir:   "/home/user/secret/observations",
		MaxUnsafeDuration: 168 * time.Hour,
		SanitizePaths:     false,
	}

	result, err := run.Execute(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Without sanitization, directory paths should appear in JSON
	for _, issue := range result.Diagnostics.Issues {
		data, _ := json.Marshal(issue.Evidence)
		jsonStr := string(data)
		if !strings.Contains(jsonStr, "/home/user/secret/") {
			t.Errorf("expected full path in evidence without sanitization, got: %s", jsonStr)
		}
	}
}

func TestValidateEvidence_RedactPaths_True(t *testing.T) {
	run := appvalidation.NewRun(stubObservationRepo{}, stubControlRepo{})
	cfg := appvalidation.Config{
		ControlsDir:       "/home/user/secret/controls",
		ObservationsDir:   "/home/user/secret/observations",
		MaxUnsafeDuration: 168 * time.Hour,
		SanitizePaths:     true,
	}

	result, err := run.Execute(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// With sanitization, directory paths should be [SANITIZED] in JSON
	for _, issue := range result.Diagnostics.Issues {
		data, _ := json.Marshal(issue.Evidence)
		jsonStr := string(data)
		if strings.Contains(jsonStr, "/home/user/secret/") {
			t.Errorf("expected path to be sanitized, got: %s", jsonStr)
		}
		if !strings.Contains(jsonStr, "[SANITIZED]") {
			t.Errorf("expected [SANITIZED] in evidence, got: %s", jsonStr)
		}
	}
}
