package kernel

import "testing"

func TestDefaultPolicy_ProxyEnvVars(t *testing.T) {
	p := DefaultPolicy()
	vars := p.ProxyEnvVars()
	if len(vars) == 0 {
		t.Fatal("expected non-empty proxy env vars")
	}
	// Verify well-known entries exist.
	want := map[string]bool{
		"HTTP_PROXY":  false,
		"HTTPS_PROXY": false,
		"http_proxy":  false,
		"https_proxy": false,
	}
	for _, v := range vars {
		if _, ok := want[v]; ok {
			want[v] = true
		}
	}
	for k, found := range want {
		if !found {
			t.Errorf("expected %q in ProxyEnvVars", k)
		}
	}
}

func TestDefaultPolicy_ProtectedPaths(t *testing.T) {
	p := DefaultPolicy()
	paths := p.ProtectedPaths()
	if len(paths) == 0 {
		t.Fatal("expected non-empty protected paths")
	}
	found := false
	for _, path := range paths {
		if path == "internal/core/kernel/airgap.go" {
			found = true
		}
	}
	if !found {
		t.Error("expected airgap.go in protected paths")
	}
}

func TestDefaultPolicy_BannedImports(t *testing.T) {
	p := DefaultPolicy()
	imports := p.BannedImports()
	if len(imports) == 0 {
		t.Fatal("expected non-empty banned imports")
	}
	found := false
	for _, imp := range imports {
		if imp == `"os/exec"` {
			found = true
		}
	}
	if !found {
		t.Error("expected \"os/exec\" in banned imports")
	}
}

func TestDefaultPolicy_BannedCredentialKeys(t *testing.T) {
	p := DefaultPolicy()
	keys := p.BannedCredentialKeys()
	if len(keys) == 0 {
		t.Fatal("expected non-empty banned credential keys")
	}
	found := false
	for _, k := range keys {
		if k == "AWS_ACCESS_KEY_ID" {
			found = true
		}
	}
	if !found {
		t.Error("expected AWS_ACCESS_KEY_ID in banned credential keys")
	}
}

func TestDefaultPolicy_ProviderPermissions(t *testing.T) {
	p := DefaultPolicy()
	perms := p.ProviderPermissions("aws")
	if len(perms) == 0 {
		t.Fatal("expected non-empty AWS permissions")
	}
	found := false
	for _, perm := range perms {
		if perm == "s3:GetBucketAcl" {
			found = true
		}
	}
	if !found {
		t.Error("expected s3:GetBucketAcl in AWS permissions")
	}

	// Unknown provider returns nil/empty.
	unknown := p.ProviderPermissions("unknown_provider")
	if len(unknown) != 0 {
		t.Errorf("expected empty permissions for unknown provider, got %d", len(unknown))
	}
}

func TestDefaultPolicy_IsImportAllowed(t *testing.T) {
	p := DefaultPolicy()

	tests := []struct {
		name    string
		relPath string
		imp     string
		want    bool
	}{
		{
			name:    "allowed os/exec in gitinfo",
			relPath: "internal/adapters/gitinfo/repo.go",
			imp:     `"os/exec"`,
			want:    true,
		},
		{
			name:    "allowed os/exec in govulncheck",
			relPath: "internal/adapters/govulncheck/runner.go",
			imp:     `"os/exec"`,
			want:    true,
		},
		{
			name:    "allowed text/template in ui",
			relPath: "internal/cli/ui/template.go",
			imp:     `"text/template"`,
			want:    true,
		},
		{
			name:    "disallowed os/exec in random file",
			relPath: "internal/something/other.go",
			imp:     `"os/exec"`,
			want:    false,
		},
		{
			name:    "disallowed net/http in allowed file",
			relPath: "internal/adapters/gitinfo/repo.go",
			imp:     `"net/http"`,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.IsImportAllowed(tt.relPath, tt.imp)
			if got != tt.want {
				t.Errorf("IsImportAllowed(%q, %q) = %v, want %v", tt.relPath, tt.imp, got, tt.want)
			}
		})
	}
}

func TestDefaultPolicy_SlicesAreIndependent(t *testing.T) {
	p := DefaultPolicy()
	vars1 := p.ProxyEnvVars()
	vars2 := p.ProxyEnvVars()
	if len(vars1) == 0 {
		t.Fatal("expected non-empty proxy env vars")
	}
	vars1[0] = "MUTATED"
	if vars2[0] == "MUTATED" {
		t.Error("modifying returned slice should not affect subsequent calls")
	}
}
