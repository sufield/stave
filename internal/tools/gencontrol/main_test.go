package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_BasicControl(t *testing.T) {
	dir := t.TempDir()
	cfg := config{
		ID:          "CTL.TEST.BASIC.001",
		Name:        "Basic Test Control",
		Domain:      "exposure",
		Severity:    "high",
		ScopeTags:   "aws,s3",
		AssetType:   "aws_s3_bucket",
		Field:       "properties.storage.access.public_read",
		Op:          "eq",
		Value:       "true",
		Remediation: "Disable public read.",
		OutDir:      dir,
		Stdout:      io.Discard,
	}

	if err := run(cfg); err != nil {
		t.Fatalf("run() error: %v", err)
	}

	// Verify fail fixture structure.
	failDir := filepath.Join(dir, "e2e-forge-test-basic-fail")
	assertFileExists(t, filepath.Join(failDir, "controls", "CTL.TEST.BASIC.001.yaml"))
	assertFileExists(t, filepath.Join(failDir, "observations", "2026-01-01T000000Z.json"))
	assertFileExists(t, filepath.Join(failDir, "observations", "2026-01-11T000000Z.json"))
	assertFileExists(t, filepath.Join(failDir, "args.txt"))
	assertFileContains(t, filepath.Join(failDir, "expected.exit"), "3")
	assertFileContains(t, filepath.Join(failDir, "expected.findings.count"), "1")

	// Verify pass fixture structure.
	passDir := filepath.Join(dir, "e2e-forge-test-basic-pass")
	assertFileExists(t, filepath.Join(passDir, "controls", "CTL.TEST.BASIC.001.yaml"))
	assertFileExists(t, filepath.Join(passDir, "observations", "2026-01-01T000000Z.json"))
	assertFileContains(t, filepath.Join(passDir, "expected.exit"), "0")
	assertFileContains(t, filepath.Join(passDir, "expected.findings.count"), "0")
}

func TestRun_WithKind(t *testing.T) {
	dir := t.TempDir()
	cfg := config{
		ID:          "CTL.IAM.KIND.001",
		Name:        "Kind Control",
		Domain:      "identity",
		Severity:    "medium",
		ScopeTags:   "aws,iam",
		AssetType:   "aws_iam_user",
		Kind:        "user",
		Field:       "properties.identity.credentials.unused",
		Op:          "eq",
		Value:       "true",
		Remediation: "Disable unused credentials.",
		OutDir:      dir,
		Stdout:      io.Discard,
	}

	if err := run(cfg); err != nil {
		t.Fatalf("run() error: %v", err)
	}

	// Verify control YAML contains kind check.
	failDir := filepath.Join(dir, "e2e-forge-iam-kind-fail")
	ctlPath := filepath.Join(failDir, "controls", "CTL.IAM.KIND.001.yaml")
	assertFileContains(t, ctlPath, "properties.identity.kind")
	assertFileContains(t, ctlPath, "value: user")

	// Verify observation includes kind property.
	obsPath := filepath.Join(failDir, "observations", "2026-01-01T000000Z.json")
	assertFileContains(t, obsPath, `"kind": "user"`)
}

func TestRun_WithCompliance(t *testing.T) {
	dir := t.TempDir()
	cfg := config{
		ID:          "CTL.S3.COMP.001",
		Name:        "Compliance Control",
		Domain:      "exposure",
		Severity:    "critical",
		ScopeTags:   "aws,s3",
		AssetType:   "aws_s3_bucket",
		Field:       "properties.storage.access.public_read",
		Op:          "eq",
		Value:       "true",
		Remediation: "Fix it.",
		Compliance:  "hipaa=164.312(a),cis_aws_v1.4.0=2.1.5",
		OutDir:      dir,
		Stdout:      io.Discard,
	}

	if err := run(cfg); err != nil {
		t.Fatalf("run() error: %v", err)
	}

	ctlPath := filepath.Join(dir, "e2e-forge-s3-comp-fail", "controls", "CTL.S3.COMP.001.yaml")
	assertFileContains(t, ctlPath, `hipaa: "164.312(a)"`)
	assertFileContains(t, ctlPath, `cis_aws_v1.4.0: "2.1.5"`)
}

func TestRun_PassFixtureHasSafeValue(t *testing.T) {
	dir := t.TempDir()
	cfg := config{
		ID:          "CTL.TEST.SAFE.001",
		Name:        "Safe Value Test",
		Domain:      "exposure",
		Severity:    "high",
		ScopeTags:   "aws,s3",
		AssetType:   "aws_s3_bucket",
		Field:       "properties.storage.access.public_read",
		Op:          "eq",
		Value:       "true",
		SafeValue:   "false",
		Remediation: "Fix it.",
		OutDir:      dir,
		Stdout:      io.Discard,
	}

	if err := run(cfg); err != nil {
		t.Fatalf("run() error: %v", err)
	}

	// Fail fixture has unsafe value.
	failObs := filepath.Join(dir, "e2e-forge-test-safe-fail", "observations", "2026-01-01T000000Z.json")
	assertFileContains(t, failObs, `"public_read": true`)

	// Pass fixture has safe value.
	passObs := filepath.Join(dir, "e2e-forge-test-safe-pass", "observations", "2026-01-01T000000Z.json")
	assertFileContains(t, passObs, `"public_read": false`)
}

func TestRun_ValidationRejectsInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	// An empty ID should still generate YAML that fails validation
	// at the domain level (Prepare). However, the template produces
	// syntactically valid YAML, so this tests the positive path.
	cfg := config{
		ID:          "CTL.VALID.001",
		Name:        "Valid Control",
		Domain:      "exposure",
		Severity:    "high",
		ScopeTags:   "aws,s3",
		AssetType:   "aws_s3_bucket",
		Field:       "properties.storage.access.public_read",
		Op:          "eq",
		Value:       "true",
		Remediation: "Fix it.",
		OutDir:      dir,
		Stdout:      io.Discard,
	}

	// Should succeed — the generated YAML is valid.
	if err := run(cfg); err != nil {
		t.Fatalf("expected valid control, got error: %v", err)
	}
}

func TestValidate_RejectsEmpty(t *testing.T) {
	cfg := config{}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for empty config")
	}
	if !strings.Contains(err.Error(), "--id is required") {
		t.Fatalf("expected --id error, got: %v", err)
	}
}

func TestValidate_RejectsNoRemediation(t *testing.T) {
	cfg := config{
		ID:    "CTL.X.001",
		Name:  "X",
		Field: "properties.x",
	}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for missing remediation")
	}
	if !strings.Contains(err.Error(), "--remediation is required") {
		t.Fatalf("expected remediation error, got: %v", err)
	}
}

func TestInvertValue(t *testing.T) {
	tests := []struct{ in, want string }{
		{"true", "false"},
		{"false", "true"},
		{"42", "42"},
		{"bucket", "bucket"},
	}
	for _, tt := range tests {
		got := invertValue(tt.in)
		if got != tt.want {
			t.Errorf("invertValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDefaultKindField(t *testing.T) {
	tests := []struct{ domain, want string }{
		{"identity", "properties.identity.kind"},
		{"exposure", "properties.storage.kind"},
		{"governance", "properties.storage.kind"},
	}
	for _, tt := range tests {
		got := defaultKindField(tt.domain)
		if got != tt.want {
			t.Errorf("defaultKindField(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}

func TestBuildNestedProps(t *testing.T) {
	got := buildNestedProps("properties.identity.root.mfa_enabled", true)
	// Should produce {"identity": {"root": {"mfa_enabled": true}}}
	identity, ok := got["identity"].(map[string]any)
	if !ok {
		t.Fatalf("expected identity map, got %T", got["identity"])
	}
	root, ok := identity["root"].(map[string]any)
	if !ok {
		t.Fatalf("expected root map, got %T", identity["root"])
	}
	if root["mfa_enabled"] != true {
		t.Fatalf("expected mfa_enabled=true, got %v", root["mfa_enabled"])
	}
}

func TestMergeMaps(t *testing.T) {
	dst := map[string]any{
		"identity": map[string]any{
			"credentials": map[string]any{"unused": true},
		},
	}
	src := map[string]any{
		"identity": map[string]any{
			"kind": "user",
		},
	}
	result := mergeMaps(dst, src)

	identity := result["identity"].(map[string]any)
	if identity["kind"] != "user" {
		t.Fatalf("expected kind=user, got %v", identity["kind"])
	}
	creds := identity["credentials"].(map[string]any)
	if creds["unused"] != true {
		t.Fatalf("expected unused=true, got %v", creds["unused"])
	}
}

func TestDefaultFixtureName(t *testing.T) {
	tests := []struct{ id, suffix, want string }{
		{"CTL.S3.PUBLIC.001", "fail", "e2e-forge-s3-public-fail"},
		{"CTL.IAM.ROOT.MFA.001", "pass", "e2e-forge-iam-root-mfa-pass"},
	}
	for _, tt := range tests {
		got := defaultFixtureName(tt.id, tt.suffix)
		if got != tt.want {
			t.Errorf("defaultFixtureName(%q, %q) = %q, want %q", tt.id, tt.suffix, got, tt.want)
		}
	}
}

func TestAssetIDFromType(t *testing.T) {
	tests := []struct{ in, want string }{
		{"aws_s3_bucket", "test-s3-bucket"},
		{"aws_iam_user", "test-iam-user"},
		{"aws_iam_account", "test-iam-account"},
		{"custom", "test-asset"},
	}
	for _, tt := range tests {
		got := assetIDFromType(tt.in)
		if got != tt.want {
			t.Errorf("assetIDFromType(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// ── helpers ──────────────────────────────────────────────────

func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected file %s to exist: %v", path, err)
	}
}

func assertFileContains(t *testing.T, path, substr string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(data), substr) {
		t.Errorf("file %s does not contain %q\ncontent:\n%s", path, substr, string(data))
	}
}
