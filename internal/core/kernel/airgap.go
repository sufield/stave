package kernel

import (
	"slices"
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
	cloudPermissions     map[string][]string // keyed by provider (e.g., "aws", "azure")
}

// DefaultPolicy returns the standard air-gap restriction policy.
// This is the single source of truth for the system's isolation requirements.
func DefaultPolicy() AirgapPolicy {
	return AirgapPolicy{
		protectedPaths: []string{
			"internal/core/kernel/airgap.go",
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
		bannedCredentialKeys: []string{
			"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
			"AWS_PROFILE", "AWS_DEFAULT_REGION", "AWS_SHARED_CREDENTIALS_FILE",
			"GOOGLE_APPLICATION_CREDENTIALS",
			"AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
		},
		cloudPermissions: map[string][]string{
			"aws": {
				"s3:GetBucketAcl",
				"s3:GetBucketLogging",
				"s3:GetBucketObjectLockConfiguration",
				"s3:GetBucketPolicy",
				"s3:GetBucketPublicAccessBlock",
				"s3:GetBucketTagging",
				"s3:GetBucketVersioning",
				"s3:GetEncryptionConfiguration",
				"s3:GetLifecycleConfiguration",
				"s3:ListAllMyBuckets",
			},
		},
	}
}

// ProxyEnvVars returns the proxy environment variable names checked by this policy.
func (p AirgapPolicy) ProxyEnvVars() []string {
	return slices.Clone(p.proxyEnvVars)
}

// ProviderPermissions returns the required permissions for a specific
// cloud provider (e.g., "aws"). This keeps vendor strings out of the struct fields.
func (p AirgapPolicy) ProviderPermissions(provider string) []string {
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
