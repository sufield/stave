package validatecmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

func writeFile(t *testing.T, name, body string) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}

func TestValidateContent_ContractControlV1(t *testing.T) {
	data := writeFile(t, "ctl.yaml", `
dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: Buckets should stay private
description: Public buckets increase exposure risk.
classification: state_assertion
type: unsafe_state
unsafe_predicate:
  any:
    - field: properties.storage.access.public_read
      op: eq
      value: true
`)

	res, err := ValidateContent(data, "control", "v1", true, "text", "", false, "", "", testLabel, testExec)
	if err != nil {
		t.Fatalf("expected contract validate success, got %v", err)
	}
	if res.ExitErr != nil {
		t.Fatalf("expected clean validation, got exit error %v", res.ExitErr)
	}
	if !strings.Contains(string(res.Output), "Validation passed") {
		t.Fatalf("expected validation passed output, got: %s", res.Output)
	}
}

func TestValidateContent_ContractStrictUnknownField(t *testing.T) {
	data := writeFile(t, "ctl.yaml", `
dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: Buckets should stay private
description: Public buckets increase exposure risk.
classification: state_assertion
type: unsafe_state
unsafe_predicate:
  any:
    - field: properties.storage.access.public_read
      op: eq
      value: true
unexpected: true
`)

	res, err := ValidateContent(data, "control", "v1", true, "text", "", false, "", "", testLabel, testExec)
	if err != nil {
		t.Fatalf("unexpected service error: %v", err)
	}
	if !errors.Is(res.ExitErr, appcontracts.ErrValidationFailed) {
		t.Fatalf("expected strict contract validation failure, got %v", res.ExitErr)
	}
}

func TestValidateContent_ContractRejectsInvalidControl(t *testing.T) {
	data := writeFile(t, "invalid-ctl.yaml", `
dsl_version: ctrl.v1
id: CTL.S3.PUBLIC.001
name: Invalid control
description: Invalid metadata shape
control: public_access
expect: disabled
`)

	res, err := ValidateContent(data, "control", "v1", true, "text", "", false, "", "", testLabel, testExec)
	if err != nil {
		t.Fatalf("unexpected service error: %v", err)
	}
	if !errors.Is(res.ExitErr, appcontracts.ErrValidationFailed) {
		t.Fatalf("expected contract validation failure for invalid shape, got %v", res.ExitErr)
	}
}
