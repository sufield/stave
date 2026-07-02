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

// airgapRegistry holds the vendor-contributed air-gap inputs — banned
// credential env-var names and per-vendor cloud permissions. Bundling both with
// the single RWMutex that guards them keeps the lock and the data it protects
// in one type (registration happens once at startup, so a shared lock is
// ample). The kernel ships it empty; providers contribute via
// RegisterBannedCredentialKeys / RegisterCloudPermissions from their Register()
// entrypoint, and DefaultPolicy snapshots it at call time.
type airgapRegistry struct {
	mu               sync.RWMutex
	bannedCredKeys   []string
	cloudPermissions map[Vendor][]string
}

// registerBannedKeys appends env-var names, skipping empties and duplicates.
func (r *airgapRegistry) registerBannedKeys(keys ...string) {
	if len(keys) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, k := range keys {
		if k == "" || slices.Contains(r.bannedCredKeys, k) {
			continue
		}
		r.bannedCredKeys = append(r.bannedCredKeys, k)
	}
}

// registerCloudPermissions appends per-vendor permission strings, skipping
// empties and per-vendor duplicates.
func (r *airgapRegistry) registerCloudPermissions(vendor Vendor, perms ...string) {
	if vendor == "" || len(perms) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing := r.cloudPermissions[vendor]
	for _, p := range perms {
		if p == "" || slices.Contains(existing, p) {
			continue
		}
		existing = append(existing, p)
	}
	r.cloudPermissions[vendor] = existing
}

// snapshotBannedKeys returns a copy of the banned-credential-keys list.
func (r *airgapRegistry) snapshotBannedKeys() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.bannedCredKeys)
}

// snapshotCloudPermissions returns a deep copy of the per-vendor permissions.
func (r *airgapRegistry) snapshotCloudPermissions() map[Vendor][]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[Vendor][]string, len(r.cloudPermissions))
	for v, perms := range r.cloudPermissions {
		out[v] = slices.Clone(perms)
	}
	return out
}

// airgapInputs is the process-wide registry of vendor-contributed air-gap
// inputs — one cohesive instance rather than two loose mutex+collection pairs.
var airgapInputs = &airgapRegistry{cloudPermissions: map[Vendor][]string{}}

// RegisterBannedCredentialKeys appends the given environment-variable
// names to the air-gap policy's banned-credential-keys list.
// Duplicates are skipped. Provider packages call this from Register().
func RegisterBannedCredentialKeys(keys ...string) {
	airgapInputs.registerBannedKeys(keys...)
}

// RegisterCloudPermissions appends the given IAM/equivalent permission
// strings to the air-gap policy's per-vendor permission list.
// Duplicates within a vendor are skipped. Provider packages call this
// from Register().
func RegisterCloudPermissions(vendor Vendor, perms ...string) {
	airgapInputs.registerCloudPermissions(vendor, perms...)
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
			"internal/adapters/govulncheck/runner.go": {
				`"os/exec"`: {},
			},
			// The pager spawns the user's $PAGER (less/more) to display human
			// output AFTER evaluation. Like the govulncheck runner above, this is
			// a scoped, display-only subprocess — it touches no network and is
			// never on the evaluation path, so the air-gap guarantee holds.
			"internal/cli/ui/pager.go": {
				`"os/exec"`: {},
			},
			"internal/cli/ui/template.go": {
				`"text/template"`: {},
			},
			// services.go has a struct tag yaml:"plugin" — not an import.
			"pkg/stave/services.go": {
				`"plugin"`: {},
			},
		},
		bannedCredentialKeys: airgapInputs.snapshotBannedKeys(),
		cloudPermissions:     airgapInputs.snapshotCloudPermissions(),
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
