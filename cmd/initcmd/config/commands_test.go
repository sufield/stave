package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/env"
)

func TestConfigShow_DefaultsText(t *testing.T) {
	t.Setenv(env.MaxUnsafe.Name, "")
	t.Setenv(env.SnapshotRetention.Name, "")
	t.Setenv(env.RetentionTier.Name, "")
	t.Setenv(env.CIFailurePolicy.Name, "")

	temp := t.TempDir()
	chdirForConfigTest(t, temp)

	root := getTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"config", "show"})

	if err := root.Execute(); err != nil {
		t.Fatalf("config show failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "max_unsafe: 168h (default)") {
		t.Fatalf("expected default max_unsafe in output, got: %s", out)
	}
	if !strings.Contains(out, "snapshot_retention: 30d (default)") {
		t.Fatalf("expected default snapshot_retention in output, got: %s", out)
	}
	if !strings.Contains(out, "default_retention_tier: critical (default)") {
		t.Fatalf("expected default retention tier in output, got: %s", out)
	}
}

func TestConfigShow_ConfigAndEnvSourcesJSON(t *testing.T) {
	temp := t.TempDir()
	chdirForConfigTest(t, temp)

	cfgPath := filepath.Join(temp, appconfig.ProjectConfigFile)
	cfg := "max_unsafe: 96h\nsnapshot_retention: 45d\ndefault_retention_tier: non_critical\nsnapshot_retention_tiers:\n  critical:\n    older_than: 30d\n  non_critical:\n    older_than: 14d\nci_failure_policy: fail_on_new_violation\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv(env.SnapshotRetention.Name, "7d")

	root := getTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"config", "show", "--format", "json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("config show failed: %v", err)
	}

	var out appconfig.EffectiveConfig
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("decode output: %v\noutput=%s", err, buf.String())
	}
	configBase := filepath.Base(out.ConfigFile)
	if configBase != appconfig.ProjectConfigFile {
		t.Fatalf("config file base=%q want %q", configBase, appconfig.ProjectConfigFile)
	}
	if out.MaxUnsafeDuration.Value != "96h" {
		t.Fatalf("max_unsafe=%q want 96h", out.MaxUnsafeDuration.Value)
	}
	if !strings.HasSuffix(out.MaxUnsafeDuration.Source, appconfig.ProjectConfigFile+":max_unsafe") {
		t.Fatalf("max_unsafe source=%q", out.MaxUnsafeDuration.Source)
	}
	if out.SnapshotRetention.Value != "7d" {
		t.Fatalf("snapshot_retention=%q want 7d", out.SnapshotRetention.Value)
	}
	if out.SnapshotRetention.Source != "env:"+env.SnapshotRetention.Name {
		t.Fatalf("snapshot_retention source=%q", out.SnapshotRetention.Source)
	}
}

func TestConfigGetAndSet(t *testing.T) {
	temp := t.TempDir()
	chdirForConfigTest(t, temp)

	root := getTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"config", "set", "max_unsafe", "72h"})
	if err := root.Execute(); err != nil {
		t.Fatalf("config set failed: %v", err)
	}
	if !strings.Contains(buf.String(), "Set max_unsafe=72h") {
		t.Fatalf("unexpected set output: %s", buf.String())
	}

	buf.Reset()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"config", "get", "max_unsafe"})
	if err := root.Execute(); err != nil {
		t.Fatalf("config get failed: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != "72h" {
		t.Fatalf("got %q want 72h", got)
	}
}

func TestConfigSetRetentionTierKey(t *testing.T) {
	temp := t.TempDir()
	chdirForConfigTest(t, temp)

	root := getTestRootCmd()
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))
	root.SetArgs([]string{"config", "set", "snapshot_retention_tiers.non_critical", "14d"})
	if err := root.Execute(); err != nil {
		t.Fatalf("config set failed: %v", err)
	}

	cfgBytes, err := os.ReadFile(filepath.Join(temp, appconfig.ProjectConfigFile))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(cfgBytes), "older_than: 14d") {
		t.Fatalf("expected tier older_than value in config, got:\n%s", string(cfgBytes))
	}
}

func TestConfigSetRejectsInvalidValue(t *testing.T) {
	temp := t.TempDir()
	chdirForConfigTest(t, temp)

	root := getTestRootCmd()
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))
	root.SetArgs([]string{"config", "set", "max_unsafe", "abc"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected invalid duration error")
	}
	if !strings.Contains(err.Error(), "invalid") || !strings.Contains(err.Error(), "max_unsafe") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigDeleteKey(t *testing.T) {
	temp := t.TempDir()
	chdirForConfigTest(t, temp)

	// Set a value first
	root := getTestRootCmd()
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))
	root.SetArgs([]string{"config", "set", "max_unsafe", "24h"})
	if err := root.Execute(); err != nil {
		t.Fatalf("config set failed: %v", err)
	}

	// Verify it was set
	buf := new(bytes.Buffer)
	root = getTestRootCmd()
	root.SetOut(buf)
	root.SetErr(new(bytes.Buffer))
	root.SetArgs([]string{"config", "get", "max_unsafe"})
	if err := root.Execute(); err != nil {
		t.Fatalf("config get failed: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != "24h" {
		t.Fatalf("got %q want 24h", got)
	}

	// Delete it
	buf.Reset()
	root = getTestRootCmd()
	root.SetOut(buf)
	root.SetErr(new(bytes.Buffer))
	root.SetArgs([]string{"config", "delete", "max_unsafe", "--force"})
	if err := root.Execute(); err != nil {
		t.Fatalf("config delete failed: %v", err)
	}
	if !strings.Contains(buf.String(), "Deleted max_unsafe") {
		t.Fatalf("unexpected delete output: %s", buf.String())
	}

	// Verify it reverted to default
	buf.Reset()
	root = getTestRootCmd()
	root.SetOut(buf)
	root.SetErr(new(bytes.Buffer))
	root.SetArgs([]string{"config", "get", "max_unsafe"})
	if err := root.Execute(); err != nil {
		t.Fatalf("config get after delete failed: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != "168h" {
		t.Fatalf("got %q want 168h (default)", got)
	}
}

func TestConfigDeleteNoConfig(t *testing.T) {
	temp := t.TempDir()
	chdirForConfigTest(t, temp)

	root := getTestRootCmd()
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))
	root.SetArgs([]string{"config", "delete", "max_unsafe", "--force"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when no config file exists")
	}
	if !strings.Contains(err.Error(), "no config file found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func chdirForConfigTest(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp: %v", err)
	}
	t.Cleanup(func() {
		if chdirErr := os.Chdir(prev); chdirErr != nil {
			t.Fatalf("restore wd: %v", chdirErr)
		}
	})
}
