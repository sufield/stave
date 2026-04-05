package policy

import (
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
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
		if !stmt.GrantsReadAccess() {
			continue
		}

		for _, resource := range stmt.Resource {
			prefix := parseObjectPrefix(resource)
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
	return kernel.ObjectPrefix(kernel.EnsureTrailingSlash(prefix))
}
