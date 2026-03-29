package evaluate

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestEvaluate_HIPAA_Integration(t *testing.T) {
	cmd := NewCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{
		"--snapshot", "testdata/snapshots/hipaa_fixture.json",
		"--profile", "hipaa",
		"--format", "text",
	})

	err := cmd.Execute()

	// Expect exit code 1 (CRITICAL failures).
	if err == nil {
		t.Fatal("expected error for CRITICAL failures, got nil")
	}
	code := ExitCode(err)
	if code != 1 {
		t.Errorf("exit code: got %d, want 1 (error: %v)", code, err)
	}

	output := stdout.String()

	// Must contain HIPAA profile header.
	if !strings.Contains(output, "HIPAA Security Rule") {
		t.Error("output should contain profile name")
	}

	// Must contain CRITICAL section with failures.
	if !strings.Contains(output, "CRITICAL") {
		t.Error("output should contain CRITICAL section")
	}

	// Must have at least two CRITICAL failures.
	critCount := strings.Count(output, "[FAIL] ")
	if critCount < 2 {
		t.Errorf("expected at least 2 FAIL entries, got %d", critCount)
	}

	// Must contain HIPAA CFR citations.
	citations := []string{
		"§164.312(a)(1)",
		"§164.312(a)(2)(iv)",
		"§164.312(b)",
		"§164.312(c)(1)",
		"§164.312(e)(2)(ii)",
	}
	for _, cite := range citations {
		if !strings.Contains(output, cite) {
			t.Errorf("output should contain HIPAA citation %s", cite)
		}
	}

	// Must contain compound risk (ACCESS.001 + ACCESS.002 both fail).
	if !strings.Contains(output, "COMPOUND") || !strings.Contains(output, "lateral movement") {
		t.Error("output should contain COMPOUND.001 finding about lateral movement")
	}

	// Must contain BAA disclaimer.
	if !strings.Contains(output, "BAA with AWS") {
		t.Error("output should contain BAA disclaimer")
	}

	// Must contain overall FAIL.
	if !strings.Contains(output, "Overall: FAIL") {
		t.Error("output should contain Overall: FAIL")
	}
}

func TestEvaluate_HIPAA_JSON(t *testing.T) {
	cmd := NewCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{
		"--snapshot", "testdata/snapshots/hipaa_fixture.json",
		"--profile", "hipaa",
		"--format", "json",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for CRITICAL failures")
	}

	output := stdout.String()
	if !strings.Contains(output, `"pass": false`) {
		t.Error("JSON should contain pass: false")
	}
	if !strings.Contains(output, `"compound_findings"`) {
		t.Error("JSON should contain compound_findings")
	}
}

func TestEvaluate_UnknownProfile(t *testing.T) {
	cmd := NewCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{
		"--snapshot", "testdata/snapshots/hipaa_fixture.json",
		"--profile", "nonexistent",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
	if ExitCode(err) != 2 {
		t.Errorf("exit code: got %d, want 2", ExitCode(err))
	}
}

func TestEvaluate_WithException(t *testing.T) {
	// The exception_stave.yaml declares ACCESS.001 exception with CONTROLS.001 as compensating.
	// The fixture has CONTROLS.001 passing (encryption enabled with AES256).
	// So the exception should be VALID and ACCESS.001 becomes ACKNOWLEDGED.
	cmd := NewCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{
		"--snapshot", "testdata/snapshots/hipaa_fixture.json",
		"--profile", "hipaa",
		"--format", "text",
	})

	// Place the stave.yaml next to the snapshot.
	// It's already at testdata/snapshots/exception_stave.yaml — we need it as stave.yaml.
	origStave := "testdata/snapshots/stave.yaml"
	data, _ := os.ReadFile("testdata/snapshots/exception_stave.yaml")
	_ = os.WriteFile(origStave, data, 0o644)
	defer os.Remove(origStave)

	err := cmd.Execute()
	// Still expect exit code 1 due to other CRITICAL failures.
	if err == nil {
		t.Fatal("expected error for remaining CRITICAL failures")
	}

	output := stdout.String()

	// ACKNOWLEDGED should appear in output.
	if !strings.Contains(output, "ACKNOWLEDGED") {
		t.Error("output should contain ACKNOWLEDGED for the exception")
	}

	// Acknowledged Exceptions section should appear.
	if !strings.Contains(output, "Acknowledged Exceptions") {
		t.Error("output should contain Acknowledged Exceptions section")
	}

	// The rationale should appear.
	if !strings.Contains(output, "CloudFront") {
		t.Error("output should contain exception rationale mentioning CloudFront")
	}
}

func TestEvaluate_MissingSnapshot(t *testing.T) {
	cmd := NewCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{
		"--snapshot", "testdata/snapshots/nonexistent.json",
		"--profile", "hipaa",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing snapshot")
	}
	if ExitCode(err) != 2 {
		t.Errorf("exit code: got %d, want 2", ExitCode(err))
	}
}
