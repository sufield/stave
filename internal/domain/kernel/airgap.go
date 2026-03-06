package kernel

// AirgapPolicy groups all air-gap restriction data into a single struct.
type AirgapPolicy struct {
	PolicyPaths             []string
	ProxyEnvVars            []string
	BannedRuntimeImports    []string
	AllowedImportByFile     map[string]map[string]bool
	BannedCredentialEnvVars []string
}

// DefaultPolicy returns an AirgapPolicy populated with all air-gap restriction
// data. This is the single source of truth for air-gap policy constants.
func DefaultPolicy() AirgapPolicy {
	return AirgapPolicy{
		PolicyPaths: []string{
			"internal/domain/kernel/airgap.go",
		},
		ProxyEnvVars: []string{
			"HTTP_PROXY",
			"HTTPS_PROXY",
			"ALL_PROXY",
			"http_proxy",
			"https_proxy",
			"all_proxy",
		},
		BannedRuntimeImports: []string{
			`"os/exec"`,
			`"plugin"`,
			`"text/template"`,
			`"html/template"`,
			`"unsafe"`,
			`"net/http"`,
			`"net/rpc"`,
			`"crypto/tls"`,
		},
		AllowedImportByFile: map[string]map[string]bool{
			"cmd/report_output.go": {
				`"text/template"`: true,
			},
			"internal/adapters/gitinfo/repo.go": {
				`"os/exec"`: true,
			},
			"internal/adapters/govulncheck/runner.go": {
				`"os/exec"`: true,
			},
		},
		BannedCredentialEnvVars: []string{
			"AWS_ACCESS_KEY_ID",
			"AWS_SECRET_ACCESS_KEY",
			"AWS_SESSION_TOKEN",
			"AWS_PROFILE",
			"AWS_DEFAULT_REGION",
			"AWS_SHARED_CREDENTIALS_FILE",
			"GOOGLE_APPLICATION_CREDENTIALS",
			"AZURE_CLIENT_ID",
			"AZURE_CLIENT_SECRET",
			"AZURE_TENANT_ID",
		},
	}
}

// IsImportAllowed reports whether a banned import is explicitly allowlisted
// for a specific file within this policy.
func (p AirgapPolicy) IsImportAllowed(relPath, imp string) bool {
	if byFile, ok := p.AllowedImportByFile[relPath]; ok {
		return byFile[imp]
	}
	return false
}
