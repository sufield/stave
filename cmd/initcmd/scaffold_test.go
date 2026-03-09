package initcmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCreatesScaffold(t *testing.T) {
	projectDir := filepath.Join(t.TempDir(), "stave-project")

	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"init", "--dir", projectDir})

	if err := root.Execute(); err != nil {
		t.Fatalf("init command failed: %v", err)
	}

	dirs := []string{
		"controls",
		"snapshots/raw",
		"observations",
		"output",
	}
	for _, rel := range dirs {
		if fi, err := os.Stat(filepath.Join(projectDir, rel)); err != nil || !fi.IsDir() {
			t.Fatalf("expected directory %s to exist", rel)
		}
	}

	if _, statErr := os.Stat(filepath.Join(projectDir, ".gitignore")); statErr != nil {
		t.Fatalf("expected .gitignore to exist: %v", statErr)
	}
	userCfgExamplePath := filepath.Join(projectDir, "cli.yaml")
	userCfgExampleData, err := os.ReadFile(userCfgExamplePath)
	if err != nil {
		t.Fatalf("expected cli.yaml to exist: %v", err)
	}
	if !strings.Contains(string(userCfgExampleData), "# cli_defaults:") {
		t.Fatalf("expected user config example to include commented cli_defaults block")
	}
	configPath := filepath.Join(projectDir, projectConfigFile)
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("expected %s to exist: %v", projectConfigFile, err)
	}
	if !strings.Contains(string(configData), "max_unsafe: "+defaultMaxUnsafeDuration) {
		t.Fatalf("expected %s to include max_unsafe %q, got %q", projectConfigFile, defaultMaxUnsafeDuration, string(configData))
	}
	if !strings.Contains(string(configData), "snapshot_retention: "+defaultSnapshotRetention) {
		t.Fatalf("expected %s to include snapshot_retention %q, got %q", projectConfigFile, defaultSnapshotRetention, string(configData))
	}
	if !strings.Contains(string(configData), "default_retention_tier: "+defaultRetentionTier) {
		t.Fatalf("expected %s to include default_retention_tier %q, got %q", projectConfigFile, defaultRetentionTier, string(configData))
	}
	if !strings.Contains(string(configData), "snapshot_retention_tiers:") {
		t.Fatalf("expected %s to include snapshot_retention_tiers block, got %q", projectConfigFile, string(configData))
	}
	if !strings.Contains(string(configData), "enabled_control_packs:") || !strings.Contains(string(configData), "- s3") {
		t.Fatalf("expected %s to include enabled_control_packs with s3, got %q", projectConfigFile, string(configData))
	}
	if !strings.Contains(string(configData), "ci_failure_policy: "+defaultCIFailurePolicy) {
		t.Fatalf("expected %s to include ci_failure_policy %q, got %q", projectConfigFile, defaultCIFailurePolicy, string(configData))
	}
	if !strings.Contains(string(configData), "capture_cadence: daily") {
		t.Fatalf("expected %s to include capture_cadence %q, got %q", projectConfigFile, "daily", string(configData))
	}
	if !strings.Contains(string(configData), "snapshot_filename_template: YYYY-MM-DDT000000Z.json") {
		t.Fatalf("expected %s to include daily naming template, got %q", projectConfigFile, string(configData))
	}
	lockPath := filepath.Join(projectDir, "stave.lock")
	lockData, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("expected stave.lock to exist: %v", err)
	}
	if !strings.Contains(string(lockData), "schema_version: lock.v1") {
		t.Fatalf("expected stave.lock schema_version, got %q", string(lockData))
	}

	// Sample files replace .gitkeep in controls/ and snapshots/raw/
	invSample, err := os.ReadFile(filepath.Join(projectDir, "controls/control.sample.yaml"))
	if err != nil {
		t.Fatalf("expected controls/control.sample.yaml to exist: %v", err)
	}
	if !strings.Contains(string(invSample), "# dsl_version: ctrl.v1") {
		t.Fatalf("expected control sample to contain dsl_version comment, got %q", string(invSample))
	}
	if _, statErr := os.Stat(filepath.Join(projectDir, "snapshots/raw/observation.sample.json")); statErr != nil {
		t.Fatalf("expected snapshots/raw/observation.sample.json to exist: %v", statErr)
	}
	staveSample, err := os.ReadFile(filepath.Join(projectDir, "stave.sample.yaml"))
	if err != nil {
		t.Fatalf("expected stave.sample.yaml to exist: %v", err)
	}
	if !strings.Contains(string(staveSample), "# max_unsafe:") {
		t.Fatalf("expected stave.sample.yaml to contain max_unsafe comment, got %q", string(staveSample))
	}
}

func TestInitSkipsExistingFilesWithoutForce(t *testing.T) {
	projectDir := filepath.Join(t.TempDir(), "stave-project")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(projectDir, projectConfigFile)
	if err := os.WriteFile(target, []byte("custom-content\n"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"init", "--dir", projectDir})
	if err := root.Execute(); err != nil {
		t.Fatalf("init command failed: %v", err)
	}

	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(after) != "custom-content\n" {
		t.Fatalf("expected existing file to be preserved, got: %s", string(after))
	}
}

func TestInitForceOverwritesExistingFiles(t *testing.T) {
	projectDir := filepath.Join(t.TempDir(), "stave-project")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(projectDir, projectConfigFile)
	if err := os.WriteFile(target, []byte("old\n"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"init", "--dir", projectDir, "--force"})
	if err := root.Execute(); err != nil {
		t.Fatalf("init command failed: %v", err)
	}

	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if !strings.Contains(string(after), "max_unsafe:") {
		t.Fatalf("expected stave.yaml content after force overwrite, got: %s", string(after))
	}
}
