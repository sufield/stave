package kernel

import (
	"slices"
	"sync"
)

// AirgapPolicy defines abstract security boundaries.
// The domain defines the structure of the policy; vendor-specific
// values are organized by provider to keep the kernel neutral.
type AirgapPolicy struct {
	protectedPaths       []string
	proxyEnvVars         []string
	bannedImports        []string
	allowedImports       map[string]map[string]struct{}
	bannedCredentialKeys []string
	cloudPermissions     map[Vendor][]string // keyed by provider (e.g., "aws", "azure")
}

// Vendor-specific air-gap inputs live in package-level registries so
// provider packages contribute their keys and permissions from
// init() / Register(). DefaultPolicy snapshots the registries at
// call time. The kernel ships these registries empty; AWS seeds via
// providers/aws.Register, GCP and Azure register their own keys
// when those providers ship.
var (
	bannedCredentialKeysMu sync.RWMutex
	bannedCredentialKeys   = []string{}

	cloudPermissionsMu sync.RWMutex
	cloudPermissions   = map[Vendor][]string{}
)

// RegisterBannedCredentialKeys appends the given environment-variable
// names to the air-gap policy's banned-credential-keys list.
// Duplicates are skipped. Provider packages call this from init().
func RegisterBannedCredentialKeys(keys ...string) {
	if len(keys) == 0 {
		return
	}
	bannedCredentialKeysMu.Lock()
	defer bannedCredentialKeysMu.Unlock()
	for _, k := range keys {
		if k == "" || slices.Contains(bannedCredentialKeys, k) {
			continue
		}
		bannedCredentialKeys = append(bannedCredentialKeys, k)
	}
}

// RegisterCloudPermissions appends the given IAM/equivalent
// permission strings to the air-gap policy's per-vendor permission
// list. Duplicates within a vendor are skipped. Provider packages
// call this from init().
func RegisterCloudPermissions(vendor Vendor, perms ...string) {
	if vendor == "" || len(perms) == 0 {
		return
	}
	cloudPermissionsMu.Lock()
	defer cloudPermissionsMu.Unlock()
	existing := cloudPermissions[vendor]
	for _, p := range perms {
		if p == "" || slices.Contains(existing, p) {
			continue
		}
		existing = append(existing, p)
	}
	cloudPermissions[vendor] = existing
}

// snapshotBannedCredentialKeys returns a copy of the registry.
func snapshotBannedCredentialKeys() []string {
	bannedCredentialKeysMu.RLock()
	defer bannedCredentialKeysMu.RUnlock()
	return slices.Clone(bannedCredentialKeys)
}

// snapshotCloudPermissions returns a deep copy of the registry.
func snapshotCloudPermissions() map[Vendor][]string {
	cloudPermissionsMu.RLock()
	defer cloudPermissionsMu.RUnlock()
	out := make(map[Vendor][]string, len(cloudPermissions))
	for v, perms := range cloudPermissions {
		out[v] = slices.Clone(perms)
	}
	return out
}

// DefaultPolicy returns the standard air-gap restriction policy.
// This is the single source of truth for the system's isolation requirements.
func DefaultPolicy() AirgapPolicy {
	return AirgapPolicy{
		protectedPaths: []string{
			"internal/core/kernel/airgap.go",
			// aws.Register names AWS credential env vars when seeding
			// the banned-keys list. Like airgap.go, the file declares
			// the policy itself; the air-gap test must not flag it.
			"internal/platform/providers/aws/aws.go",
		},
		proxyEnvVars: []string{
			"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
			"http_proxy", "https_proxy", "all_proxy",
		},
		bannedImports: []string{
			`"os/exec"`, `"plugin"`, `"text/template"`, `"html/template"`,
			`"unsafe"`, `"net/http"`, `"net/rpc"`, `"crypto/tls"`,
		},
		allowedImports: map[string]map[string]struct{}{
			"internal/adapters/gitinfo/repo.go": {
				`"os/exec"`: {},
			},
			"internal/adapters/govulncheck/runner.go": {
				`"os/exec"`: {},
			},
			"internal/cli/ui/template.go": {
				`"text/template"`: {},
			},
		},
		bannedCredentialKeys: snapshotBannedCredentialKeys(),
		cloudPermissions:     snapshotCloudPermissions(),
	}
}

// ProxyEnvVars returns the proxy environment variable names checked by this policy.
func (p AirgapPolicy) ProxyEnvVars() []string {
	return slices.Clone(p.proxyEnvVars)
}

// ProviderPermissions returns the required permissions for a specific
// cloud provider (e.g., "aws"). This keeps vendor strings out of the struct fields.
func (p AirgapPolicy) ProviderPermissions(provider Vendor) []string {
	return slices.Clone(p.cloudPermissions[provider])
}

// IsImportAllowed reports whether a banned import is explicitly
// allowlisted for a specific file.
func (p AirgapPolicy) IsImportAllowed(relPath, imp string) bool {
	if allowed, ok := p.allowedImports[relPath]; ok {
		_, allowed := allowed[imp]
		return allowed
	}
	return false
}

// ProtectedPaths returns the file paths that define this policy.
func (p AirgapPolicy) ProtectedPaths() []string {
	return slices.Clone(p.protectedPaths)
}

// BannedImports returns the import strings banned under this policy.
func (p AirgapPolicy) BannedImports() []string {
	return slices.Clone(p.bannedImports)
}

// BannedCredentialKeys returns the list of sensitive environment variables
// that should not be present in an air-gapped environment.
func (p AirgapPolicy) BannedCredentialKeys() []string {
	return slices.Clone(p.bannedCredentialKeys)
}
