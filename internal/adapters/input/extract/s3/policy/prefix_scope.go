package policy

import (
	"strconv"
	"strings"

	"github.com/sufield/stave/internal/domain/kernel"
)

// PrefixScopeAnalysis contains the public-read prefix scopes extracted from a bucket policy.
type PrefixScopeAnalysis struct {
	Scopes        []kernel.ObjectPrefix
	SourceByScope map[kernel.ObjectPrefix]string
}

// PrefixScopeAnalysis extracts public-read prefix scopes from the parsed bucket policy.
func (e *Engine) PrefixScopeAnalysis() PrefixScopeAnalysis {
	var scopes []kernel.ObjectPrefix
	sourceByScope := make(map[kernel.ObjectPrefix]string)
	seen := make(map[kernel.ObjectPrefix]bool)

	for i, stmt := range e.policy.Statement {
		if !stmt.Effect.IsAllow() {
			continue
		}
		if !IsPublicPrincipal(stmt.principalAny()) {
			continue
		}

		actions := []string(stmt.Action)
		if !hasPublicReadAction(actions) {
			continue
		}

		resources := []string(stmt.Resource)
		scope := scopeFromResources(resources)
		if scope == "" || seen[scope] {
			continue
		}
		seen[scope] = true
		scopes = append(scopes, scope)

		sid := strings.TrimSpace(stmt.Sid)
		if sid == "" {
			sid = "stmt-" + strconv.Itoa(i)
		}
		sourceByScope[scope] = sid
	}

	return PrefixScopeAnalysis{
		Scopes:        scopes,
		SourceByScope: sourceByScope,
	}
}

func hasPublicReadAction(actions []string) bool {
	for _, action := range actions {
		a := strings.ToLower(strings.TrimSpace(action))
		if a == "*" || a == "s3:*" || a == "s3:getobject" {
			return true
		}
	}
	return false
}

func scopeFromResources(resources []string) kernel.ObjectPrefix {
	for _, res := range resources {
		scope := scopeFromResourcePattern(res)
		if scope != "" {
			return scope
		}
	}
	return ""
}

func scopeFromResourcePattern(resource string) kernel.ObjectPrefix {
	parts := strings.SplitN(strings.TrimSpace(resource), ":::", 2)
	if len(parts) != 2 {
		return ""
	}
	after := parts[1]
	_, path, hasPath := strings.Cut(after, "/")
	if !hasPath {
		return ""
	}
	if path == "*" {
		return kernel.WildcardPrefix
	}
	if before, ok := strings.CutSuffix(path, "/*"); ok {
		scope := before
		if scope == "" {
			return kernel.WildcardPrefix
		}
		if !strings.HasSuffix(scope, "/") {
			scope += "/"
		}
		return kernel.ObjectPrefix(scope)
	}
	return ""
}
