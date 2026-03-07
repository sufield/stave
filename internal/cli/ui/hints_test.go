package ui

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestEvaluateErrorWithHint_MissingObservations(t *testing.T) {
	err := EvaluateErrorWithHint(errors.New("--observations not accessible: ./observations"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Next: stave ingest --profile aws-s3") {
		t.Fatalf("expected ingest hint, got: %v", err)
	}
	if !strings.Contains(err.Error(), "More info: run 'stave docs search") {
		t.Fatalf("expected local docs reference, got: %v", err)
	}
}

func TestEvaluateErrorWithHint_SchemaValidation(t *testing.T) {
	err := EvaluateErrorWithHint(errors.New("failed to load observations: schema validation failed for observations/one.json"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Next: stave validate --controls ./controls --observations ./observations") {
		t.Fatalf("expected validate hint, got: %v", err)
	}
}

func TestEvaluateErrorWithHint_NoControls(t *testing.T) {
	err := EvaluateErrorWithHint(errors.New("no controls in ./controls (expected .yaml files with dsl_version: ctrl.v1)"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Next: stave generate control --id CTL.S3.PUBLIC.901 --out ./controls/CTL.S3.PUBLIC.901.yaml") {
		t.Fatalf("expected generate hint, got: %v", err)
	}
}

func TestEvaluateErrorWithHint_ControlSourceConflict(t *testing.T) {
	err := EvaluateErrorWithHint(errors.New("cannot combine explicit --controls with enabled_control_packs; remove one source to keep selection deterministic"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Next: stave status") {
		t.Fatalf("expected status hint, got: %v", err)
	}
}

type typedHintTestError struct {
	msg string
}

func (e *typedHintTestError) Error() string { return e.msg }

func TestWithHint_PreservesSentinelAndOriginal(t *testing.T) {
	base := fmt.Errorf("wrapped: %w", &typedHintTestError{msg: "boom"})
	err := WithHint(base, ErrHintNoControls)

	if !errors.Is(err, ErrHintNoControls) {
		t.Fatalf("expected sentinel match, got: %v", err)
	}
	var typed *typedHintTestError
	if !errors.As(err, &typed) {
		t.Fatalf("expected typed error match, got: %v", err)
	}
}

func TestSuggestForError_UsesSentinelLookup(t *testing.T) {
	err := WithHint(errors.New("irrelevant message"), ErrHintNoSnapshots)
	hint := SuggestForError(err)
	if hint.NextCommand == "" {
		t.Fatalf("expected sentinel hint, got: %+v", hint)
	}
	if !strings.Contains(hint.NextCommand, "stave ingest") {
		t.Fatalf("expected ingest command, got: %q", hint.NextCommand)
	}
}

func TestBuildSearchQueryFromError_LimitsTokenCount(t *testing.T) {
	query := buildSearchQueryFromError("one two three four five six seven")
	if query != "one two three four five" {
		t.Fatalf("expected limited query, got %q", query)
	}
}
