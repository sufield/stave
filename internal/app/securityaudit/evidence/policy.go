package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

type networkDeclaration struct {
	RuntimeNetworkNone bool     `json:"runtime_network_none"`
	Violations         []string `json:"violations"`
	ProxyEnvVarsSet    []string `json:"proxy_env_vars_set"`
	BannedImports      []string `json:"banned_imports"`
	GeneratedAt        string   `json:"generated_at"`
}

type filesystemDeclaration struct {
	Reads       []string `json:"reads"`
	Writes      []string `json:"writes"`
	GeneratedAt string   `json:"generated_at"`
}

type DefaultPolicyInspector struct {
	ReadFile     func(path string) ([]byte, error)
	StatFile     func(string) (fs.FileInfo, error)
	Getenv       func(string) string
	IsPrivileged func() bool
	WalkDir      func(string, WalkFunc) error
}

func (d DefaultPolicyInspector) Inspect(_ context.Context, req Params) (PolicyInspectionSnapshot, error) {
	root, err := findRepoRootWith(req.Cwd, func() (string, error) { return req.Cwd, nil }, d.StatFile)
	if err != nil {
		return PolicyInspectionSnapshot{}, err
	}

	runtimeViolations, inspectErr := inspectForBannedRuntimeImports(root, d.ReadFile, d.WalkDir)
	credentialViolations, credErr := inspectForCredentialEnvRefs(root, d.ReadFile, d.WalkDir)
	if inspectErr != nil || credErr != nil {
		return PolicyInspectionSnapshot{}, errors.Join(inspectErr, credErr)
	}

	proxyVars := setProxyVars(d.Getenv)
	reads := []string{
		"Input directories provided by --controls and --observations",
		"Optional project config: stave.yaml",
		"Optional release bundle via --release-bundle-dir",
		"Environment: STAVE_* and shell proxy variables",
	}
	writes := []string{
		"Main security report (--out or default in --out-dir)",
		"Bundle artifacts under --out-dir",
		"Optional log output via --log-file",
	}

	networkDecl := networkDeclaration{
		RuntimeNetworkNone: len(runtimeViolations) == 0,
		Violations:         runtimeViolations,
		ProxyEnvVarsSet:    proxyVars,
		BannedImports:      kernel.DefaultPolicy().BannedImports(),
		GeneratedAt:        req.Now.UTC().Format(time.RFC3339),
	}
	filesystemDecl := filesystemDeclaration{
		Reads:       reads,
		Writes:      writes,
		GeneratedAt: req.Now.UTC().Format(time.RFC3339),
	}
	networkJSON, _ := json.MarshalIndent(networkDecl, "", "  ")
	filesystemJSON, _ := json.MarshalIndent(filesystemDecl, "", "  ")

	redactionPath := filepath.Join(root, "internal", "sanitize")
	_, redactionErr := d.StatFile(redactionPath)
	loggingPath := filepath.Join(root, "internal", "platform", "logging")
	_, loggingErr := d.StatFile(loggingPath)

	runningPrivileged := false
	if runtime.GOOS != "windows" && d.IsPrivileged != nil {
		runningPrivileged = d.IsPrivileged()
	}

	iamActions := kernel.DefaultPolicy().ProviderPermissions("aws")

	return PolicyInspectionSnapshot{
		Network: NetworkInspection{
			RuntimeNetworkOK:  len(runtimeViolations) == 0,
			RuntimeViolations: runtimeViolations,
			NetworkDeclJSON:   append(networkJSON, '\n'),
		},
		Credential: CredentialInspection{
			CredentialPolicyOK:   len(credentialViolations) == 0,
			CredentialViolations: credentialViolations,
		},
		Filesystem: FilesystemInspection{
			FilesystemReads:    reads,
			FilesystemWrites:   writes,
			FilesystemDeclJSON: append(filesystemJSON, '\n'),
		},
		Operational: OperationalInspection{
			RedactionPolicyOK:      redactionErr == nil,
			TelemetryDeclaredNone:  len(runtimeViolations) == 0,
			AuditLoggingConfigured: loggingErr == nil,
			RunningAsPrivileged:    runningPrivileged,
		},
		ProxyVarsSet: proxyVars,
		IAMActions:   iamActions,
	}, nil
}

func setProxyVars(getenv func(string) string) []string {
	proxyVarNames := kernel.DefaultPolicy().ProxyEnvVars()
	out := make([]string, 0, len(proxyVarNames))
	for _, key := range proxyVarNames {
		if strings.TrimSpace(getenv(key)) == "" {
			continue
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// sourceMatch is called for each source file with its relative path and content.
// It returns any violations found for that file.
type sourceMatch func(relPath, content string) []string

// inspectSourceFiles walks root, reads each non-test, non-vendor .go file,
// and calls matchFn to collect violations.
func inspectSourceFiles(root string, matchFn sourceMatch, readFile func(string) ([]byte, error), walkDir func(string, WalkFunc) error) ([]string, error) {
	excludedDirs := map[string]bool{"vendor": true}
	var violations []string
	err := walkDir(root, func(path string, info fs.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if !shouldInspectPath(rel, excludedDirs) {
			return nil
		}
		data, readErr := readFile(path)
		if readErr != nil {
			return readErr
		}
		violations = append(violations, matchFn(rel, string(data))...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(violations)
	return violations, nil
}

// shouldInspectPath returns true if the relative path should be inspected,
// filtering out policy paths and excluded directories.
func shouldInspectPath(relPath string, excludedDirs map[string]bool) bool {
	if slices.Contains(kernel.DefaultPolicy().ProtectedPaths(), relPath) {
		return false
	}
	for dir := range excludedDirs {
		if strings.HasPrefix(relPath, dir+string(filepath.Separator)) || relPath == dir {
			return false
		}
	}
	return true
}

func inspectForBannedRuntimeImports(root string, readFile func(string) ([]byte, error), walkDir func(string, WalkFunc) error) ([]string, error) {
	return inspectSourceFiles(root, func(relPath, content string) []string {
		var hits []string
		for _, banned := range kernel.DefaultPolicy().BannedImports() {
			if strings.Contains(content, banned) && !kernel.DefaultPolicy().IsImportAllowed(relPath, banned) {
				hits = append(hits, relPath+": imports "+banned)
			}
		}
		return hits
	}, readFile, walkDir)
}

func inspectForCredentialEnvRefs(root string, readFile func(string) ([]byte, error), walkDir func(string, WalkFunc) error) ([]string, error) {
	return inspectSourceFiles(root, func(relPath, content string) []string {
		var hits []string
		for _, envVar := range kernel.DefaultPolicy().BannedCredentialKeys() {
			if strings.Contains(content, envVar) {
				hits = append(hits, relPath+": references "+envVar)
			}
		}
		return hits
	}, readFile, walkDir)
}
