package iam

import (
	"encoding/json"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
)

// AWSTrustedPrincipals records the AWS-principal-side trust
// surface of a single role's trust policy: which exact principal
// ARNs are admitted, which entire AWS accounts are root-trusted,
// and whether the trust is wildcarded. It is the Iter-4 cousin
// of the Iter-3 ServiceTrusts side-channel — same probing
// strategy (raw JSON, not iam.Statement), different output
// shape because AWS-principal trust expansions and service-
// principal trust expansions feed different walker paths.
//
// Why this is a side-channel rather than parsed into Statement:
// the iam.Statement parser drops the Principal field entirely
// (only Effect / Action / Resource / Condition survive). Test
// fixtures stuff principals into the Resource field as a
// workaround; real-world AWS trust policies use Principal: {AWS:
// "..."}, which is invisible to the existing walker. Iter 4
// closes the gap for the account-root pattern — the foundational
// case for cross-account compromise propagation per
// gap-prompt.md:16.
type AWSTrustedPrincipals struct {
	// AccountRoots holds the set of account IDs whose every
	// principal is admitted via `arn:aws:iam::<acct>:root` (or
	// the bare account number form, which AWS also accepts).
	AccountRoots []string

	// ExactARNs holds the set of specific principal ARNs the
	// trust policy admits (Principal: {AWS: "arn:aws:iam::1:role/x"}).
	// Already exact, so the walker can match by direct equality.
	ExactARNs []string

	// Wildcard reports whether the trust policy admits Principal: "*"
	// at the top level WITHOUT a narrowing condition. A bare
	// `Principal: "*"` is rare in practice (and dangerous) but
	// surfaced here so the walker can flag it. Conditions like
	// aws:PrincipalOrgID are NOT consumed in v1; that is the
	// Iter 4 v2 follow-up scope.
	Wildcard bool
}

// ExtractAWSTrustedPrincipals scans every CloudIdentity's
// trust-policy JSON and returns, per role ARN, the AWS principal
// surface the policy admits for sts:AssumeRole (and federated
// variants). Service principals are NOT included here — Iter 3's
// ExtractServiceTrusts owns that side-channel.
//
// The returned map is keyed by principal ARN; entries with no
// AWS-principal trust at all are omitted. Roles whose trust
// policies admit only service principals will not appear, which
// is the correct behavior — they are reachable only through the
// service-execution walker, not the assume walker.
func ExtractAWSTrustedPrincipals(snap *asset.Snapshot) map[string]AWSTrustedPrincipals {
	if snap == nil {
		return nil
	}
	out := make(map[string]AWSTrustedPrincipals, len(snap.Identities))
	for i := range snap.Identities {
		id := &snap.Identities[i]
		raw := stringProperty(id.Properties, "identity", "trust_policy_json")
		if raw == "" {
			continue
		}
		trust := parseAWSPrincipalsAllowingAssume(raw)
		if len(trust.AccountRoots) == 0 && len(trust.ExactARNs) == 0 && !trust.Wildcard {
			continue
		}
		out[string(id.ID)] = trust
	}
	return out
}

// parseAWSPrincipalsAllowingAssume probes the raw trust JSON for
// AWS-principal entries on Allow + sts:AssumeRole-compatible
// statements. Returns an empty AWSTrustedPrincipals on parse
// failure or when no AWS principal is referenced.
//
// Reuses the trustPolicyServiceProbe shape from service_trusts.go
// because the Effect / Action / Principal triple is the same
// data-shape both extractors care about.
func parseAWSPrincipalsAllowingAssume(rawJSON string) AWSTrustedPrincipals {
	trimmed := strings.TrimSpace(rawJSON)
	if trimmed == "" {
		return AWSTrustedPrincipals{}
	}
	var doc trustPolicyServiceProbe
	if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
		return AWSTrustedPrincipals{}
	}
	roots := make(map[string]struct{})
	exacts := make(map[string]struct{})
	wildcard := false
	for i := range doc.Statement {
		stmt := &doc.Statement[i]
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		if !statementActionIncludesAssume(stmt.Action) {
			continue
		}
		extractAWSPrincipals(stmt.Principal, roots, exacts, &wildcard)
	}
	return AWSTrustedPrincipals{
		AccountRoots: setToSortedSlice(roots),
		ExactARNs:    setToSortedSlice(exacts),
		Wildcard:     wildcard,
	}
}

// extractAWSPrincipals walks a Principal block and routes each
// AWS-side entry into the appropriate bucket (account-root vs.
// exact ARN). Mutates the maps/flag in place to avoid allocating
// per-statement.
func extractAWSPrincipals(raw any, roots, exacts map[string]struct{}, wildcard *bool) {
	if raw == nil {
		return
	}
	// Principal: "*" — the bare-string form, top-level wildcard.
	if s, ok := raw.(string); ok && s == "*" {
		*wildcard = true
		return
	}
	principalMap, ok := raw.(map[string]any)
	if !ok {
		return
	}
	awsRaw, hasAWS := principalMap["AWS"]
	if !hasAWS {
		return
	}
	switch v := awsRaw.(type) {
	case string:
		classifyAWSPrincipal(v, roots, exacts, wildcard)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				classifyAWSPrincipal(s, roots, exacts, wildcard)
			}
		}
	}
}

// classifyAWSPrincipal sorts a single Principal: AWS entry into
// the appropriate bucket. AWS accepts three forms:
//   - "arn:aws:iam::<acct>:root"   → account-root trust
//   - "<acct>" (bare account number) → equivalent to :root
//   - "arn:aws:iam::<acct>:..."     → exact-principal trust
//   - "*"                           → wildcard (rare but legal)
func classifyAWSPrincipal(value string, roots, exacts map[string]struct{}, wildcard *bool) {
	v := strings.TrimSpace(value)
	if v == "" {
		return
	}
	if v == "*" {
		*wildcard = true
		return
	}
	if isAccountRootARN(v) {
		if acct := extractAccountIDFromRootARN(v); acct != "" {
			roots[acct] = struct{}{}
		}
		return
	}
	if isBareAccountID(v) {
		roots[v] = struct{}{}
		return
	}
	exacts[v] = struct{}{}
}

// isAccountRootARN reports whether s is the AWS canonical
// account-root form `arn:aws:iam::<acct>:root`.
func isAccountRootARN(s string) bool {
	const prefix = "arn:aws:iam::"
	const suffix = ":root"
	return strings.HasPrefix(s, prefix) && strings.HasSuffix(s, suffix)
}

// extractAccountIDFromRootARN returns the account ID embedded in
// an account-root ARN. Empty string on malformed input.
func extractAccountIDFromRootARN(s string) string {
	const prefix = "arn:aws:iam::"
	const suffix = ":root"
	if !isAccountRootARN(s) {
		return ""
	}
	body := s[len(prefix) : len(s)-len(suffix)]
	if !isBareAccountID(body) {
		return ""
	}
	return body
}

// isBareAccountID reports whether s is a 12-digit AWS account
// number. AWS allows the bare-number form as a synonym for the
// :root ARN in trust policies.
func isBareAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// setToSortedSlice produces a deterministic slice from a string
// set so the returned AWSTrustedPrincipals is stable across runs
// (important for golden-file consumers downstream).
func setToSortedSlice(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	// Insertion-sort: slice is small (typical trust policy lists
	// fewer than 10 principals); avoids importing sort for one
	// small list.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
