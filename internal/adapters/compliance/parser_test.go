package compliance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFramework_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	os.WriteFile(path, []byte(`
name: "Test Framework"
version: "1.0"
checks:
  - id: "T-1"
    service: S3
    description: "Encryption enabled"
    scope: configuration
  - id: "T-2"
    service: CloudWatch
    description: "Alarm exists"
    scope: runtime
`), 0o644)

	fw, err := ParseFramework(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fw.DisplayName() != "Test Framework" {
		t.Errorf("name = %q, want Test Framework", fw.DisplayName())
	}
	if len(fw.Checks) != 2 {
		t.Fatalf("checks = %d, want 2", len(fw.Checks))
	}
	if !fw.Checks[0].IsInScope() {
		t.Error("expected T-1 in scope")
	}
	if fw.Checks[1].IsInScope() {
		t.Error("expected T-2 out of scope")
	}
}

func TestParseFramework_LegacyStandardField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.yaml")
	os.WriteFile(path, []byte(`
standard: "CIS AWS v3.0"
checks:
  - id: "cis-1.4"
    service: IAM
    description: "No root access key"
`), 0o644)

	fw, err := ParseFramework(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fw.DisplayName() != "CIS AWS v3.0" {
		t.Errorf("name = %q, want CIS AWS v3.0", fw.DisplayName())
	}
}

func TestParseFramework_InvalidYAML_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte(`not: [valid: yaml`), 0o644)

	_, err := ParseFramework(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestParseFramework_NoChecks_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	os.WriteFile(path, []byte(`name: "Empty"\nchecks: []`), 0o644)

	_, err := ParseFramework(path)
	if err == nil {
		t.Fatal("expected error for empty checks")
	}
}

func TestCheck_NormalizedService(t *testing.T) {
	tests := []struct {
		service string
		want    string
	}{
		{"IAM", "iam"},
		{"S3", "s3"},
		{"CloudTrail", "cloudtrail"},
		{"bedrock-agentcore", "bedrockagentcore"},
	}
	for _, tt := range tests {
		c := Check{Service: tt.service}
		if got := c.NormalizedService(); got != tt.want {
			t.Errorf("NormalizedService(%q) = %q, want %q", tt.service, got, tt.want)
		}
	}
}
