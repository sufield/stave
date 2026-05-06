package iam

import (
	"encoding/json"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
)

// ExtractServiceTrusts scans every CloudIdentity in the snapshot
// for a trust-policy JSON blob and returns the set of AWS service
// principals each identity's trust policy allows for sts:AssumeRole.
// Keyed by principal ARN; the slice values are lowercased service
// names (e.g. "lambda.amazonaws.com").
//
// Why a side-channel rather than extending iam.Statement:
//
// The iam package's Statement.UnmarshalJSON does NOT decode the
// Principal field — it only captures Effect / Action / Resource /
// Condition. Trust policies parsed via ParsePolicyDocument therefore
// lose every Principal block on the way through. trustPolicyAllows
// works around this by walking stmt.Resource, which only succeeds
// when the trust policy was constructed with principals in the
// Resource field (the legacy test-fixture pattern). Real-world AWS
// trust policies use the Principal field; their service-principal
// content is invisible to the existing parser.
//
// Iter 3 needs that data to decide "does this role's trust policy
// allow lambda.amazonaws.com / cloudformation.amazonaws.com / etc.?"
// for service-execution hop detection. Rather than rewrite
// iam.Statement and risk regressing the existing flow, this
// function probes the raw trust-policy JSON with a richer schema
// and feeds the result into RoleChainInput.ServiceTrusts.
//
// Future cleanup: when iam.Statement gets a proper Principal field,
// fold this side-channel back into the parsed PolicyDocument and
// retire the standalone scan.
func ExtractServiceTrusts(snap *asset.Snapshot) map[string][]string {
	if snap == nil {
		return nil
	}
	out := make(map[string][]string, len(snap.Identities))
	for i := range snap.Identities {
		id := &snap.Identities[i]
		raw := stringProperty(id.Properties, "identity", "trust_policy_json")
		if raw == "" {
			continue
		}
		services := parseServicePrincipalsAllowingAssume(raw)
		if len(services) == 0 {
			continue
		}
		out[string(id.ID)] = services
	}
	return out
}

// trustPolicyServiceProbe is a parse-only struct that captures the
// fields of an AWS trust policy ExtractServiceTrusts cares about.
// Distinct from iam.Statement so the existing flow's struct shape
// stays untouched.
type trustPolicyServiceProbe struct {
	Statement []trustStatementServiceProbe `json:"Statement"`
}

type trustStatementServiceProbe struct {
	Effect    string `json:"Effect"`
	Action    any    `json:"Action"`
	Principal any    `json:"Principal"`
}

// parseServicePrincipalsAllowingAssume returns the lowercased set
// of service principals the trust policy permits for sts:AssumeRole
// (or wildcard variants). Returns an empty slice on parse failure
// or when no service principal is referenced.
func parseServicePrincipalsAllowingAssume(rawJSON string) []string {
	trimmed := strings.TrimSpace(rawJSON)
	if trimmed == "" {
		return nil
	}
	var doc trustPolicyServiceProbe
	if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	for i := range doc.Statement {
		stmt := &doc.Statement[i]
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		if !statementActionIncludesAssume(stmt.Action) {
			continue
		}
		for _, svc := range extractServicePrincipals(stmt.Principal) {
			seen[strings.ToLower(svc)] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for svc := range seen {
		out = append(out, svc)
	}
	return out
}

// statementActionIncludesAssume reports whether the (raw) Action
// value of a trust-policy statement includes sts:AssumeRole or one
// of the federated variants. Tolerant of string / []string wire
// shapes.
func statementActionIncludesAssume(raw any) bool {
	switch a := raw.(type) {
	case string:
		return isAssumeRoleAction(a)
	case []any:
		for _, item := range a {
			if s, ok := item.(string); ok && isAssumeRoleAction(s) {
				return true
			}
		}
	}
	return false
}

// extractServicePrincipals walks a Principal block (in any of the
// AWS-supported wire shapes) and returns service principals named
// under the "Service" key. Other principal kinds (AWS, Federated,
// CanonicalUser) are ignored — the trust-policy ARN check is
// already handled by trustPolicyAllows.
func extractServicePrincipals(raw any) []string {
	if raw == nil {
		return nil
	}
	principalMap, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	svcRaw, hasService := principalMap["Service"]
	if !hasService {
		return nil
	}
	switch v := svcRaw.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// isAssumeRoleAction recognises every AWS STS action that admits
// a principal into a role's identity. Iter 3 expands the set the
// chain walker uses elsewhere: AssumeRoleWithWebIdentity (Cognito,
// federated OIDC) and AssumeRoleWithSAML (federated SAML) are now
// hop-creating actions.
func isAssumeRoleAction(action string) bool {
	switch action {
	case "sts:AssumeRole",
		"sts:AssumeRoleWithWebIdentity",
		"sts:AssumeRoleWithSAML",
		"sts:*",
		"*":
		return true
	}
	return false
}
