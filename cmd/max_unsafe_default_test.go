package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/envvar"
)

func TestResolveMaxUnsafeDefault_Fallback(t *testing.T) {
	t.Setenv(envvar.MaxUnsafe.Name, "")
	t.Setenv(envvar.SnapshotRetention.Name, "")
	tmp := t.TempDir()
	chdirForTest(t, tmp)

	got := cmdutil.ResolveMaxUnsafeDefault()
	if got != cmdutil.DefaultMaxUnsafeDuration {
		t.Fatalf("ResolveMaxUnsafeDefault() = %q, want %q", got, cmdutil.DefaultMaxUnsafeDuration)
	}
}

func TestResolveMaxUnsafeDefault_EnvOverridesProjectFile(t *testing.T) {
	t.Setenv(envvar.MaxUnsafe.Name, "24h")
	t.Setenv(envvar.SnapshotRetention.Name, "")
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, cmdutil.ProjectConfigFile), []byte("max_unsafe: 48h\n"), 0o644); err != nil {
		t.Fatalf("write project config file: %v", err)
	}
	chdirForTest(t, tmp)

	got := cmdutil.ResolveMaxUnsafeDefault()
	if got != "24h" {
		t.Fatalf("ResolveMaxUnsafeDefault() = %q, want %q", got, "24h")
	}
}

func TestResolveMaxUnsafeDefault_ProjectFile(t *testing.T) {
	t.Setenv(envvar.MaxUnsafe.Name, "")
	t.Setenv(envvar.SnapshotRetention.Name, "")
	tmp := t.TempDir()
	root := filepath.Join(tmp, "project")
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, cmdutil.ProjectConfigFile), []byte("max_unsafe: 36h\n"), 0o644); err != nil {
		t.Fatalf("write project config file: %v", err)
	}
	chdirForTest(t, nested)

	got := cmdutil.ResolveMaxUnsafeDefault()
	if got != "36h" {
		t.Fatalf("ResolveMaxUnsafeDefault() = %q, want %q", got, "36h")
	}
}

func TestResolveMaxUnsafeDefault_UserConfigFallback(t *testing.T) {
	t.Setenv(envvar.MaxUnsafe.Name, "")
	t.Setenv(envvar.SnapshotRetention.Name, "")
	tmp := t.TempDir()
	userCfgPath := filepath.Join(tmp, "user-config.yaml")
	t.Setenv(envvar.UserConfig.Name, userCfgPath)
	if err := os.WriteFile(userCfgPath, []byte("max_unsafe: 60h\n"), 0o644); err != nil {
		t.Fatalf("write user config file: %v", err)
	}
	chdirForTest(t, tmp)

	got := cmdutil.ResolveMaxUnsafeDefault()
	if got != "60h" {
		t.Fatalf("ResolveMaxUnsafeDefault() = %q, want %q", got, "60h")
	}
}

func TestResolveSnapshotRetentionDefault_Fallback(t *testing.T) {
	t.Setenv(envvar.SnapshotRetention.Name, "")
	tmp := t.TempDir()
	chdirForTest(t, tmp)

	got := cmdutil.ResolveSnapshotRetentionDefault()
	if got != cmdutil.DefaultSnapshotRetention {
		t.Fatalf("ResolveSnapshotRetentionDefault() = %q, want %q", got, cmdutil.DefaultSnapshotRetention)
	}
}

func TestResolveSnapshotRetentionDefault_EnvOverridesProjectFile(t *testing.T) {
	t.Setenv(envvar.SnapshotRetention.Name, "10d")
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, cmdutil.ProjectConfigFile), []byte("snapshot_retention: 45d\n"), 0o644); err != nil {
		t.Fatalf("write project config file: %v", err)
	}
	chdirForTest(t, tmp)

	got := cmdutil.ResolveSnapshotRetentionDefault()
	if got != "10d" {
		t.Fatalf("ResolveSnapshotRetentionDefault() = %q, want %q", got, "10d")
	}
}

func TestResolveSnapshotRetentionDefault_ProjectFile(t *testing.T) {
	t.Setenv(envvar.SnapshotRetention.Name, "")
	tmp := t.TempDir()
	root := filepath.Join(tmp, "project")
	nested := filepath.Join(root, "x", "y")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, cmdutil.ProjectConfigFile), []byte("snapshot_retention: 21d\n"), 0o644); err != nil {
		t.Fatalf("write project config file: %v", err)
	}
	chdirForTest(t, nested)

	got := cmdutil.ResolveSnapshotRetentionDefault()
	if got != "21d" {
		t.Fatalf("ResolveSnapshotRetentionDefault() = %q, want %q", got, "21d")
	}
}

func TestResolveSnapshotRetentionDefault_UserConfigFallback(t *testing.T) {
	t.Setenv(envvar.SnapshotRetention.Name, "")
	tmp := t.TempDir()
	userCfgPath := filepath.Join(tmp, "user-config.yaml")
	t.Setenv(envvar.UserConfig.Name, userCfgPath)
	if err := os.WriteFile(userCfgPath, []byte("snapshot_retention: 21d\n"), 0o644); err != nil {
		t.Fatalf("write user config file: %v", err)
	}
	chdirForTest(t, tmp)

	got := cmdutil.ResolveSnapshotRetentionDefault()
	if got != "21d" {
		t.Fatalf("ResolveSnapshotRetentionDefault() = %q, want %q", got, "21d")
	}
}

func TestResolveCIFailurePolicyDefault_Fallback(t *testing.T) {
	t.Setenv(envvar.CIFailurePolicy.Name, "")
	tmp := t.TempDir()
	chdirForTest(t, tmp)

	got := cmdutil.ResolveCIFailurePolicyDefault()
	if got != cmdutil.DefaultCIFailurePolicy {
		t.Fatalf("ResolveCIFailurePolicyDefault() = %q, want %q", got, cmdutil.DefaultCIFailurePolicy)
	}
}

func TestResolveCIFailurePolicyDefault_EnvOverridesProjectFile(t *testing.T) {
	t.Setenv(envvar.CIFailurePolicy.Name, cmdutil.GatePolicyOverdue)
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, cmdutil.ProjectConfigFile), []byte("ci_failure_policy: "+cmdutil.GatePolicyNew+"\n"), 0o644); err != nil {
		t.Fatalf("write project config file: %v", err)
	}
	chdirForTest(t, tmp)

	got := cmdutil.ResolveCIFailurePolicyDefault()
	if got != cmdutil.GatePolicyOverdue {
		t.Fatalf("ResolveCIFailurePolicyDefault() = %q, want %q", got, cmdutil.GatePolicyOverdue)
	}
}

func TestResolveCIFailurePolicyDefault_ProjectFile(t *testing.T) {
	t.Setenv(envvar.CIFailurePolicy.Name, "")
	tmp := t.TempDir()
	root := filepath.Join(tmp, "project")
	nested := filepath.Join(root, "n", "m")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, cmdutil.ProjectConfigFile), []byte("ci_failure_policy: "+cmdutil.GatePolicyNew+"\n"), 0o644); err != nil {
		t.Fatalf("write project config file: %v", err)
	}
	chdirForTest(t, nested)

	got := cmdutil.ResolveCIFailurePolicyDefault()
	if got != cmdutil.GatePolicyNew {
		t.Fatalf("ResolveCIFailurePolicyDefault() = %q, want %q", got, cmdutil.GatePolicyNew)
	}
}

func TestResolveCIFailurePolicyDefault_UserConfigFallback(t *testing.T) {
	t.Setenv(envvar.CIFailurePolicy.Name, "")
	tmp := t.TempDir()
	userCfgPath := filepath.Join(tmp, "user-config.yaml")
	t.Setenv(envvar.UserConfig.Name, userCfgPath)
	if err := os.WriteFile(userCfgPath, []byte("ci_failure_policy: "+cmdutil.GatePolicyOverdue+"\n"), 0o644); err != nil {
		t.Fatalf("write user config file: %v", err)
	}
	chdirForTest(t, tmp)

	got := cmdutil.ResolveCIFailurePolicyDefault()
	if got != cmdutil.GatePolicyOverdue {
		t.Fatalf("ResolveCIFailurePolicyDefault() = %q, want %q", got, cmdutil.GatePolicyOverdue)
	}
}

func TestResolveAllowUnknownInputDefault_FromUserConfig(t *testing.T) {
	tmp := t.TempDir()
	userCfgPath := filepath.Join(tmp, "user-config.yaml")
	t.Setenv(envvar.UserConfig.Name, userCfgPath)
	if err := os.WriteFile(userCfgPath, []byte("cli_defaults:\n  allow_unknown_input: true\n"), 0o644); err != nil {
		t.Fatalf("write user config file: %v", err)
	}
	chdirForTest(t, tmp)

	if !cmdutil.ResolveAllowUnknownInputDefault() {
		t.Fatal("ResolveAllowUnknownInputDefault() = false, want true")
	}
}

func TestResolveCLIPathModeDefault_FromUserConfig(t *testing.T) {
	tmp := t.TempDir()
	userCfgPath := filepath.Join(tmp, "user-config.yaml")
	t.Setenv(envvar.UserConfig.Name, userCfgPath)
	if err := os.WriteFile(userCfgPath, []byte("cli_defaults:\n  path_mode: full\n"), 0o644); err != nil {
		t.Fatalf("write user config file: %v", err)
	}
	chdirForTest(t, tmp)

	if got := cmdutil.ResolvePathModeDefault(); got != "full" {
		t.Fatalf("ResolvePathModeDefault() = %q, want %q", got, "full")
	}
}

func TestResolveRetentionTierDefault_Fallback(t *testing.T) {
	t.Setenv(envvar.RetentionTier.Name, "")
	tmp := t.TempDir()
	chdirForTest(t, tmp)

	got := cmdutil.ResolveRetentionTierDefault()
	if got != cmdutil.DefaultRetentionTier {
		t.Fatalf("ResolveRetentionTierDefault() = %q, want %q", got, cmdutil.DefaultRetentionTier)
	}
}

func TestResolveSnapshotRetentionForTier_FromProjectTiers(t *testing.T) {
	t.Setenv(envvar.SnapshotRetention.Name, "")
	t.Setenv(envvar.RetentionTier.Name, "")
	tmp := t.TempDir()
	cfg := "snapshot_retention: 30d\nsnapshot_retention_tiers:\n  critical:\n    older_than: 30d\n  non_critical:\n    older_than: 14d\n"
	if err := os.WriteFile(filepath.Join(tmp, cmdutil.ProjectConfigFile), []byte(cfg), 0o644); err != nil {
		t.Fatalf("write project config file: %v", err)
	}
	chdirForTest(t, tmp)

	got := cmdutil.ResolveSnapshotRetentionForTier("non_critical")
	if got != "14d" {
		t.Fatalf("ResolveSnapshotRetentionForTier(non_critical) = %q, want %q", got, "14d")
	}
}

func TestResolveSnapshotRetentionForTier_FallsBackToGlobal(t *testing.T) {
	t.Setenv(envvar.SnapshotRetention.Name, "")
	t.Setenv(envvar.RetentionTier.Name, "")
	tmp := t.TempDir()
	cfg := "snapshot_retention: 45d\nsnapshot_retention_tiers:\n  critical:\n    older_than: 30d\n"
	if err := os.WriteFile(filepath.Join(tmp, cmdutil.ProjectConfigFile), []byte(cfg), 0o644); err != nil {
		t.Fatalf("write project config file: %v", err)
	}
	chdirForTest(t, tmp)

	got := cmdutil.ResolveSnapshotRetentionForTier("non_critical")
	if got != "45d" {
		t.Fatalf("ResolveSnapshotRetentionForTier(non_critical) = %q, want %q", got, "45d")
	}
}

func chdirForTest(t *testing.T, dir string) {
	t.Helper()
	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(prevWD); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
}
