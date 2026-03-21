//go:build architecture_tests

package kernel

import "slices"

// These methods exist to support architecture safety tests that enforce
// the airgap policy. They access unexported fields and cannot live in
// _test.go files (which are external tests in a different package).
//
// They are excluded from the production binary via the architecture_tests
// build tag. Run architecture tests with:
//
//	go test -tags architecture_tests ./...

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
