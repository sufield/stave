package policy

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// NormalizedPrincipal is the typed view of an AWS Principal field.
//
// AWS supports three top-level shapes:
//
//   - Wildcard string: "*"
//   - ARN string sugar: "arn:aws:iam::123456789012:role/Foo"
//     (the AWS evaluation engine treats this as {"AWS": "..."})
//   - Object map: {"AWS": ..., "Service": ..., "Federated": ...,
//     "CanonicalUser": ...} where each value is a string or []string.
//
// The struct flattens those forms into named slices so consumers can
// branch on principal kind via field access instead of type-asserting
// a raw JSON value. The Wildcard flag fires for either the bare "*"
// string or for "*" appearing inside the AWS list — that's what the
// existing scope classifier already treated as ScopePublic.
type NormalizedPrincipal struct {
	// Wildcard is true when the Principal is the bare "*" string OR
	// when "*" appears in any AWS / object-key value. Either form
	// resolves to ScopePublic in the AWS evaluation engine.
	Wildcard bool

	// AWSARNs holds the contents of {"AWS": ...} after string/[]string
	// normalization, INCLUDING any "*" entries (callers that need only
	// concrete ARNs use ConcreteAWSARNs).
	AWSARNs []string

	// Services holds the contents of {"Service": ...}.
	Services []string

	// Federated holds the contents of {"Federated": ...}. AWS treats
	// any Federated principal as broadly reachable, so the scope
	// classifier maps a non-empty Federated to ScopePublic.
	Federated []string

	// CanonicalUsers holds the contents of {"CanonicalUser": ...}.
	CanonicalUsers []string
}

// UnmarshalJSON populates the principal from any of the AWS-supported
// JSON shapes. A null/empty Principal is the legitimate zero principal;
// a *malformed* Principal returns an error (fail-loud) rather than
// silently becoming the zero (ScopeAccount) principal, which would mask
// public access. The error propagates up through the policy parse.
func (p *NormalizedPrincipal) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		// Fail-loud: a malformed Principal must NOT silently become the zero
		// (ScopeAccount) principal — that would mask public access. Surfacing
		// the error fails the whole policy parse, and the bucket is flagged
		// (cannot prove not-public) rather than passed.
		return fmt.Errorf("malformed Principal: %w", err)
	}
	p.populate(v)
	return nil
}

// populate fills the principal slices from the decoded JSON value.
// Split out from UnmarshalJSON so internal callers (tests, future
// builders) can construct a NormalizedPrincipal from an already-decoded
// shape without re-encoding to JSON.
func (p *NormalizedPrincipal) populate(v any) {
	switch t := v.(type) {
	case string:
		if t == wildcard {
			p.Wildcard = true
			return
		}
		// Bare ARN string is sugar for {"AWS": "..."}.
		p.AWSARNs = []string{t}
	case map[string]any:
		for key, val := range t {
			normalized := NormalizeStringOrSlice(val)
			switch strings.ToLower(key) {
			case keyAWS:
				for _, s := range normalized {
					if s == wildcard {
						p.Wildcard = true
					}
				}
				p.AWSARNs = append(p.AWSARNs, normalized...)
			case keyService:
				p.Services = append(p.Services, normalized...)
			case keyFederated:
				p.Federated = append(p.Federated, normalized...)
			case keyCanonicalUser:
				p.CanonicalUsers = append(p.CanonicalUsers, normalized...)
			case wildcard:
				// {"*": "*"} or similar — AWS treats the wildcard
				// principal-type key the same as Principal: "*".
				p.Wildcard = true
			}
		}
	}
}

// IsEmpty reports whether the principal carries no extracted entries
// at all. Useful for the "absent / unparseable Principal" sentinel
// state — equivalent to the old data==nil branch.
//
// Pointer receiver matches UnmarshalJSON / populate so the type
// presents one consistent receiver style; the cost of pointer-only
// access is negligible (the value is always reachable via the owning
// Statement). A nil receiver returns true so callers iterating
// optional principals don't have to nil-check.
func (p *NormalizedPrincipal) IsEmpty() bool {
	if p == nil {
		return true
	}
	return !p.Wildcard &&
		len(p.AWSARNs) == 0 &&
		len(p.Services) == 0 &&
		len(p.Federated) == 0 &&
		len(p.CanonicalUsers) == 0
}

// ConcreteAWSARNs returns the AWS-key entries that are not the "*"
// wildcard and are not empty strings. This is what the legacy
// extractPrincipalARNs produced.
func (p *NormalizedPrincipal) ConcreteAWSARNs() []string {
	if p == nil || len(p.AWSARNs) == 0 {
		return nil
	}
	out := make([]string, 0, len(p.AWSARNs))
	for _, arn := range p.AWSARNs {
		if arn == "" || arn == wildcard {
			continue
		}
		out = append(out, arn)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Scope classifies the principal as Public / Authenticated / Account.
// Mirrors the legacy Principal.Scope() decision tree:
//   - Wildcard or any Federated principal → Public.
//   - AWS ARN list classified per-entry: "*" wins (Public),
//     ":iam::*:root" → Authenticated, bare 12-digit account → Account.
//   - Any non-empty Service / CanonicalUser → Account.
//   - Empty principal → Account (the safe default).
func (p *NormalizedPrincipal) Scope() kernel.PrincipalScope {
	if p == nil || p.IsEmpty() {
		return kernel.ScopeAccount
	}
	if p.Wildcard {
		return kernel.ScopePublic
	}
	// A Federated principal widens scope to Public — but only a NON-EMPTY
	// entry names a real identity. NormalizeStringOrSlice("") yields [""],
	// so a {"Federated": ""} block must not be counted as public (mirrors
	// ConcreteAWSARNs dropping empty-string AWS entries).
	if hasNonEmptyString(p.Federated) {
		return kernel.ScopePublic
	}
	if len(p.AWSARNs) > 0 {
		if scope := classifyAWSARNs(p.AWSARNs); scope != kernel.ScopeAccount {
			return scope
		}
	}
	return kernel.ScopeAccount
}

// hasNonEmptyString reports whether s holds at least one non-empty entry.
// Used to distinguish a principal slice that names a real identity from
// one carrying only the empty-string placeholder NormalizeStringOrSlice
// produces for a "" value.
func hasNonEmptyString(s []string) bool {
	for _, v := range s {
		if v != "" {
			return true
		}
	}
	return false
}

// classifyAWSARNs returns the most permissive scope across the AWS
// ARN list. Holds the per-entry rule the old classifyAWSPrincipal
// applied: ":iam::*:root" → Authenticated, account-id-only → Account.
func classifyAWSARNs(arns []string) kernel.PrincipalScope {
	maxScope := kernel.ScopeAccount
	for _, arn := range arns {
		switch {
		case isWildcardPrincipal(arn):
			return kernel.ScopePublic
		case strings.Contains(arn, ":iam::*:root"):
			if kernel.ScopeAuthenticated.IsMorePermissiveThan(maxScope) {
				maxScope = kernel.ScopeAuthenticated
			}
		case isAccountIDOnly(arn):
			// already at-or-below ScopeAccount; nothing to widen
		}
	}
	return maxScope
}

// NormalizedCondition is the typed view of an AWS Condition block.
//
// Wire shape: Condition[Operator][Key][]Value where Value can appear
// as a JSON string, number, boolean, or array of strings. The typed
// shape coerces every leaf to []string so callers don't redo the
// per-leaf type-assert dance the previous analyzeCondition repeated
// at every check site.
//
// Operator names retain their original case (the legacy code lower-
// cased them inside parseOperator for matching but kept the source
// case in the structure). Keys retain original case.
type NormalizedCondition map[string]map[string][]string

// UnmarshalJSON decodes the condition block, coercing every leaf
// value to []string. A null/absent Condition is the legitimate nil map
// ("no condition"); a *malformed* Condition returns an error (fail-loud)
// rather than silently becoming nil, which would weaken TLS/auth
// guardrail checks. The error propagates up through the policy parse.
func (c *NormalizedCondition) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*c = nil
		return nil
	}
	// Decode into a generic map[string]map[string]any so we can
	// observe each leaf value's wire type (string, bool, number,
	// or array) and coerce uniformly.
	var raw map[string]map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		// Fail-loud: a malformed Condition must NOT silently vanish — dropping
		// it weakens TLS/auth guardrail checks (and scope restrictions). Surface
		// the parse error so the policy is treated as unparseable, not as
		// "no condition".
		return fmt.Errorf("malformed Condition: %w", err)
	}
	if len(raw) == 0 {
		*c = nil
		return nil
	}
	out := make(NormalizedCondition, len(raw))
	for op, keys := range raw {
		opMap := make(map[string][]string, len(keys))
		for key, val := range keys {
			opMap[key] = coerceConditionValues(val)
		}
		out[op] = opMap
	}
	*c = out
	return nil
}

// IsEmpty reports whether the condition block carries no operators.
// Equivalent to the "Condition is absent" branch in the legacy code.
func (c NormalizedCondition) IsEmpty() bool {
	return len(c) == 0
}

// Lookup returns the values for (operator, key) and a presence flag.
// Both the operator and the key match case-insensitively because AWS
// treats IAM condition operators (e.g. "Bool") and condition keys
// (e.g. "aws:SecureTransport") as case-insensitive in the policy
// evaluation engine. The stored map preserves the policy author's
// original case, so a non-canonical casing (e.g.
// {"bool":{"aws:securetransport":"false"}}) still resolves to the
// canonical lookup keys passed by callers.
func (c NormalizedCondition) Lookup(operator, key string) ([]string, bool) {
	if c == nil {
		return nil, false
	}
	for op, keys := range c {
		if !strings.EqualFold(op, operator) {
			continue
		}
		for k, vals := range keys {
			if strings.EqualFold(k, key) {
				return vals, true
			}
		}
	}
	return nil, false
}

// coerceConditionValues turns one decoded condition leaf into a string
// slice. Mirrors AWS's tolerance for mixed scalar/array inputs:
//   - string → [string]
//   - bool → ["true"] or ["false"] (matches the legacy
//     hasSecureTransportCondition's bool/string equivalence)
//   - number (float64 from json.Unmarshal into any) → string-formatted
//   - []any → recursive flatten
//   - everything else → nil (drop unrecognised leaves silently,
//     matching the legacy NormalizeStringOrSlice default)
func coerceConditionValues(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case bool:
		if x {
			return []string{"true"}
		}
		return []string{"false"}
	case float64:
		return []string{strconv.FormatFloat(x, 'g', -1, 64)}
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			out = append(out, coerceConditionValues(item)...)
		}
		return out
	}
	return nil
}
