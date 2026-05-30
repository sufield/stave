package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/env"
)

func TestResolveMaxUnsafeDefault_Fallback(t *testing.T) {
	t.Setenv(env.MaxUnsafe.Name, "")
	tmp := t.TempDir()
	chdirForTest(t, tmp)

	got := projconfig.BuildResolver().Resolver.MaxUnsafeDuration()
	if got != appconfig.DefaultMaxUnsafeDuration {
		t.Fatalf("ResolveMaxUnsafeDefault() = %q, want %q", got, appconfig.DefaultMaxUnsafeDuration)
	}
}

func TestResolveMaxUnsafeDefault_EnvOverridesProjectFile(t *testing.T) {
	t.Setenv(env.MaxUnsafe.Name, "24h")
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, appconfig.AuditPolicyFile), []byte("max_unsafe: 48h\n"), 0o644); err != nil {
		t.Fatalf("write project config file: %v", err)
	}
	chdirForTest(t, tmp)

	got := projconfig.BuildResolver().Resolver.MaxUnsafeDuration()
	if got != "24h" {
		t.Fatalf("ResolveMaxUnsafeDefault() = %q, want %q", got, "24h")
	}
}

func TestResolveMaxUnsafeDefault_ProjectFile(t *testing.T) {
	t.Setenv(env.MaxUnsafe.Name, "")
	tmp := t.TempDir()
	root := filepath.Join(tmp, "project")
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, appconfig.AuditPolicyFile), []byte("max_unsafe: 36h\n"), 0o644); err != nil {
		t.Fatalf("write project config file: %v", err)
	}
	chdirForTest(t, nested)

	got := projconfig.BuildResolver().Resolver.MaxUnsafeDuration()
	if got != "36h" {
		t.Fatalf("ResolveMaxUnsafeDefault() = %q, want %q", got, "36h")
	}
}

func TestResolveMaxUnsafeDefault_UserConfigFallback(t *testing.T) {
	t.Setenv(env.MaxUnsafe.Name, "")
	tmp := t.TempDir()
	userCfgPath := filepath.Join(tmp, "user-config.yaml")
	t.Setenv(env.UserConfig.Name, userCfgPath)
	if err := os.WriteFile(userCfgPath, []byte("max_unsafe: 60h\n"), 0o644); err != nil {
		t.Fatalf("write user config file: %v", err)
	}
	chdirForTest(t, tmp)

	got := projconfig.BuildResolver().Resolver.MaxUnsafeDuration()
	if got != "60h" {
		t.Fatalf("ResolveMaxUnsafeDefault() = %q, want %q", got, "60h")
	}
}

func TestResolveCIFailurePolicyDefault_Fallback(t *testing.T) {
	t.Setenv(env.CIFailurePolicy.Name, "")
	tmp := t.TempDir()
	chdirForTest(t, tmp)

	got := projconfig.BuildResolver().Resolver.CIFailurePolicy()
	if got != appconfig.GateStrict {
		t.Fatalf("ResolveCIFailurePolicyDefault() = %q, want %q", got, appconfig.GateStrict)
	}
}

func TestResolveCIFailurePolicyDefault_EnvOverridesProjectFile(t *testing.T) {
	t.Setenv(env.CIFailurePolicy.Name, string(appconfig.GateSLA))
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, appconfig.AuditPolicyFile), []byte("ci_failure_policy: "+string(appconfig.GateRegression)+"\n"), 0o644); err != nil {
		t.Fatalf("write project config file: %v", err)
	}
	chdirForTest(t, tmp)

	got := projconfig.BuildResolver().Resolver.CIFailurePolicy()
	if got != appconfig.GateSLA {
		t.Fatalf("ResolveCIFailurePolicyDefault() = %q, want %q", got, appconfig.GateSLA)
	}
}

func TestResolveCIFailurePolicyDefault_ProjectFile(t *testing.T) {
	t.Setenv(env.CIFailurePolicy.Name, "")
	tmp := t.TempDir()
	root := filepath.Join(tmp, "project")
	nested := filepath.Join(root, "n", "m")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, appconfig.AuditPolicyFile), []byte("ci_failure_policy: "+string(appconfig.GateRegression)+"\n"), 0o644); err != nil {
		t.Fatalf("write project config file: %v", err)
	}
	chdirForTest(t, nested)

	got := projconfig.BuildResolver().Resolver.CIFailurePolicy()
	if got != appconfig.GateRegression {
		t.Fatalf("ResolveCIFailurePolicyDefault() = %q, want %q", got, appconfig.GateRegression)
	}
}

func TestResolveCIFailurePolicyDefault_UserConfigFallback(t *testing.T) {
	t.Setenv(env.CIFailurePolicy.Name, "")
	tmp := t.TempDir()
	userCfgPath := filepath.Join(tmp, "user-config.yaml")
	t.Setenv(env.UserConfig.Name, userCfgPath)
	if err := os.WriteFile(userCfgPath, []byte("ci_failure_policy: "+string(appconfig.GateSLA)+"\n"), 0o644); err != nil {
		t.Fatalf("write user config file: %v", err)
	}
	chdirForTest(t, tmp)

	got := projconfig.BuildResolver().Resolver.CIFailurePolicy()
	if got != appconfig.GateSLA {
		t.Fatalf("ResolveCIFailurePolicyDefault() = %q, want %q", got, appconfig.GateSLA)
	}
}

func TestResolveCLIPathModeDefault_FromUserConfig(t *testing.T) {
	tmp := t.TempDir()
	userCfgPath := filepath.Join(tmp, "user-config.yaml")
	t.Setenv(env.UserConfig.Name, userCfgPath)
	if err := os.WriteFile(userCfgPath, []byte("cli_defaults:\n  path_mode: full\n"), 0o644); err != nil {
		t.Fatalf("write user config file: %v", err)
	}
	chdirForTest(t, tmp)

	if got := projconfig.BuildResolver().Resolver.PathMode(); got != "full" {
		t.Fatalf("ResolvePathModeDefault() = %q, want %q", got, "full")
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
