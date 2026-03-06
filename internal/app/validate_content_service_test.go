package app

import (
	"testing"

	appvalidation "github.com/sufield/stave/internal/app/validation"
)

func TestValidateContentService_ContractModeRuns(t *testing.T) {
	svc := appvalidation.NewContentService()

	data := []byte(`
dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: Buckets should stay private
description: Public buckets increase exposure risk.
type: unsafe_state
unsafe_predicate:
  any:
    - field: properties.storage.visibility.public_read
      op: eq
      value: true
unknown_field: true
`)

	nonStrict, err := svc.Validate(appvalidation.ExplicitRequest{
		Data:          data,
		Kind:          "control",
		SchemaVersion: "v1",
		Strict:        false,
	})
	if err != nil {
		t.Fatalf("non-strict validate error: %v", err)
	}

	_, err = svc.Validate(appvalidation.ExplicitRequest{
		Data:          data,
		Kind:          "control",
		SchemaVersion: "v1",
		Strict:        true,
	})
	if err != nil {
		t.Fatalf("strict validate error: %v", err)
	}
	if len(nonStrict.Diagnostics.Issues) == 0 {
		t.Fatal("expected contract validation to return issues for this payload")
	}
}

func TestValidateContentService_AutoModeSetsSummary(t *testing.T) {
	svc := appvalidation.NewContentService()

	ctlData := []byte(`
dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: Buckets should stay private
description: Public buckets increase exposure risk.
type: unsafe_state
unsafe_predicate:
  any:
    - field: properties.storage.visibility.public_read
      op: eq
      value: true
`)

	ctlResult, err := svc.Validate(appvalidation.AutoRequest{Data: ctlData})
	if err != nil {
		t.Fatalf("control validate error: %v", err)
	}
	if ctlResult.Summary.ControlsLoaded != 1 || ctlResult.Summary.SnapshotsLoaded != 0 {
		t.Fatalf("control summary=%+v", ctlResult.Summary)
	}

	obsData := []byte(`{"schema_version":"obs.v0.1","captured_at":"2026-01-01T00:00:00Z","assets":[]}`)
	obsResult, err := svc.Validate(appvalidation.AutoRequest{Data: obsData})
	if err != nil {
		t.Fatalf("observation validate error: %v", err)
	}
	if obsResult.Summary.SnapshotsLoaded != 1 || obsResult.Summary.ControlsLoaded != 0 {
		t.Fatalf("observation summary=%+v", obsResult.Summary)
	}
}
