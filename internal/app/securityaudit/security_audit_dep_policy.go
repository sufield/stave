package securityaudit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type defaultPolicyInspector struct{}

func (defaultPolicyInspector) Inspect(_ context.Context, req SecurityAuditRequest) (policyInspectionSnapshot, error) {
	root, err := findRepoRoot(req.Cwd)
	if err != nil {
		return policyInspectionSnapshot{}, err
	}

	runtimeViolations, inspectErr := inspectForBannedRuntimeImports(root)
	credentialViolations, credErr := inspectForCredentialEnvRefs(root)
	if inspectErr != nil || credErr != nil {
		return policyInspectionSnapshot{}, errors.Join(inspectErr, credErr)
	}

	proxyVars := setProxyVars()
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

	networkDecl := map[string]any{
		"runtime_network_none": len(runtimeViolations) == 0,
		"violations":           runtimeViolations,
		"proxy_env_vars_set":   proxyVars,
		"banned_imports":       kernel.DefaultPolicy().BannedRuntimeImports,
		"generated_at":         req.Now.UTC().Format(time.RFC3339),
	}
	filesystemDecl := map[string]any{
		"reads":        reads,
		"writes":       writes,
		"generated_at": req.Now.UTC().Format(time.RFC3339),
	}
	networkJSON, _ := json.MarshalIndent(networkDecl, "", "  ")
	filesystemJSON, _ := json.MarshalIndent(filesystemDecl, "", "  ")

	redactionPath := filepath.Join(root, "internal", "sanitize")
	_, redactionErr := os.Stat(redactionPath)
	loggingPath := filepath.Join(root, "internal", "platform", "logging")
	_, loggingErr := os.Stat(loggingPath)

	runningPrivileged := false
	if runtime.GOOS != "windows" {
		runningPrivileged = os.Geteuid() == 0
	}

	iamActions := slices.Clone(kernel.DefaultPolicy().RequiredS3IAMActions)

	return policyInspectionSnapshot{
		Network: networkInspection{
			RuntimeNetworkOK:  len(runtimeViolations) == 0,
			RuntimeViolations: runtimeViolations,
			NetworkDeclJSON:   append(networkJSON, '\n'),
		},
		Credential: credentialInspection{
			CredentialPolicyOK:   len(credentialViolations) == 0,
			CredentialViolations: credentialViolations,
		},
		Filesystem: filesystemInspection{
			FilesystemReads:    reads,
			FilesystemWrites:   writes,
			FilesystemDeclJSON: append(filesystemJSON, '\n'),
		},
		Operational: operationalInspection{
			RedactionPolicyOK:      redactionErr == nil,
			TelemetryDeclaredNone:  len(runtimeViolations) == 0,
			AuditLoggingConfigured: loggingErr == nil,
			RunningAsPrivileged:    runningPrivileged,
		},
		ProxyVarsSet: proxyVars,
		IAMActions:   iamActions,
	}, nil
}

func setProxyVars() []string {
	out := make([]string, 0, len(kernel.DefaultPolicy().ProxyEnvVars))
	for _, key := range kernel.DefaultPolicy().ProxyEnvVars {
		if strings.TrimSpace(os.Getenv(key)) == "" {
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
func inspectSourceFiles(root string, matchFn sourceMatch) ([]string, error) {
	excludedDirs := map[string]bool{"vendor": true}
	var violations []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
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
		data, readErr := fsutil.ReadFileLimited(path)
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
	if slices.Contains(kernel.DefaultPolicy().PolicyPaths, relPath) {
		return false
	}
	for dir := range excludedDirs {
		if strings.HasPrefix(relPath, dir+string(filepath.Separator)) || relPath == dir {
			return false
		}
	}
	return true
}

func inspectForBannedRuntimeImports(root string) ([]string, error) {
	return inspectSourceFiles(root, func(relPath, content string) []string {
		var hits []string
		for _, banned := range kernel.DefaultPolicy().BannedRuntimeImports {
			if strings.Contains(content, banned) && !kernel.DefaultPolicy().IsImportAllowed(relPath, banned) {
				hits = append(hits, relPath+": imports "+banned)
			}
		}
		return hits
	})
}

func inspectForCredentialEnvRefs(root string) ([]string, error) {
	return inspectSourceFiles(root, func(relPath, content string) []string {
		var hits []string
		for _, envVar := range kernel.DefaultPolicy().BannedCredentialEnvVars {
			if strings.Contains(content, envVar) {
				hits = append(hits, relPath+": references "+envVar)
			}
		}
		return hits
	})
}
