package policy

import (
	"strings"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// PrefixScopeAnalysis contains the public-read prefix scopes extracted from a bucket policy.
type PrefixScopeAnalysis struct {
	Scopes        []kernel.ObjectPrefix
	SourceByScope map[kernel.ObjectPrefix]kernel.StatementID
}

// AnalyzeScopes extracts public-read prefix scopes from the parsed bucket policy.
// It identifies which parts of the bucket are publicly accessible and which
// statement grants the access.
func (d *Document) AnalyzeScopes() PrefixScopeAnalysis {
	analysis := PrefixScopeAnalysis{
		Scopes:        []kernel.ObjectPrefix{},
		SourceByScope: make(map[kernel.ObjectPrefix]kernel.StatementID),
	}
	seen := make(map[kernel.ObjectPrefix]struct{})

	for i, stmt := range d.statements {
		if !stmt.IsPubliclyExposed() {
			continue
		}
		if !hasPublicReadAction(stmt.Action) {
			continue
		}

		for _, res := range stmt.Resource {
			prefix := parseObjectPrefix(res)
			if prefix == "" {
				continue
			}
			if _, exists := seen[prefix]; exists {
				continue
			}
			seen[prefix] = struct{}{}
			analysis.Scopes = append(analysis.Scopes, prefix)
			analysis.SourceByScope[prefix] = stmt.StatementID(i)
		}
	}

	return analysis
}

// hasPublicReadAction checks for S3 actions that expose object data.
func hasPublicReadAction(actions []string) bool {
	for _, action := range actions {
		a := strings.ToLower(action)
		if a == wildcard || a == s3Wildcard || a == actionGetObject {
			return true
		}
	}
	return false
}

// parseObjectPrefix converts an AWS S3 ARN into a kernel.ObjectPrefix.
// Example: "arn:aws:s3:::my-bucket/logs/*" → "logs/"
func parseObjectPrefix(resource string) kernel.ObjectPrefix {
	_, path, found := strings.Cut(resource, ":::")
	if !found {
		return ""
	}

	_, key, found := strings.Cut(path, "/")
	if !found {
		return ""
	}

	if key == wildcard {
		return kernel.WildcardPrefix
	}

	prefix, found := strings.CutSuffix(key, "/*")
	if !found {
		return ""
	}
	if prefix == "" {
		return kernel.WildcardPrefix
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return kernel.ObjectPrefix(prefix)
}
