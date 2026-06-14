package kernel

import "testing"

func TestDefaultPolicy_ProxyEnvVars(t *testing.T) {
	p := DefaultPolicy()
	vars := p.ProxyEnvVars()
	if len(vars) == 0 {
		t.Fatal("expected non-empty proxy env vars")
	}
	found := make(map[string]struct{})
	for _, v := range vars {
		found[v] = struct{}{}
	}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if _, ok := found[k]; !ok {
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

func TestDefaultPolicy_BannedCredentialKeys_Registration(t *testing.T) {
	// The kernel ships with an empty banned-credential-keys list;
	// providers register their own. Verify the registration round-
	// trip (vendor-neutral mechanism test). AWS-specific assertions
	// live alongside aws.Register in internal/platform/providers/aws.
	const sentinel = "STAVE_KERNEL_TEST_BANNED_KEY"
	RegisterBannedCredentialKeys(sentinel)
	keys := DefaultPolicy().BannedCredentialKeys()
	found := false
	for _, k := range keys {
		if k == sentinel {
			found = true
		}
	}
	if !found {
		t.Errorf("registered key %q missing from DefaultPolicy().BannedCredentialKeys()", sentinel)
	}
}

func TestDefaultPolicy_ProviderPermissions_Registration(t *testing.T) {
	// Same shape as the credential-keys test: round-trip a
	// vendor-neutral sentinel through RegisterCloudPermissions and
	// confirm DefaultPolicy surfaces it.
	const testVendor Vendor = "stave-kernel-test"
	const sentinel = "stave:TestPermission"
	RegisterCloudPermissions(testVendor, sentinel)
	perms := DefaultPolicy().ProviderPermissions(testVendor)
	if len(perms) == 0 {
		t.Fatalf("expected non-empty permissions for %q, got 0", testVendor)
	}
	found := false
	for _, perm := range perms {
		if perm == sentinel {
			found = true
		}
	}
	if !found {
		t.Errorf("registered permission %q missing from DefaultPolicy().ProviderPermissions(%q)", sentinel, testVendor)
	}

	// Unknown provider returns nil/empty.
	unknown := DefaultPolicy().ProviderPermissions("never_registered_vendor")
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
			relPath: "internal/adapters/govulncheck/runner.go",
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
