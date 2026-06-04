package compliance

import (
	"fmt"
	"strings"

	s3policy "github.com/sufield/stave/internal/platform/providers/aws/s3/policy"
)

// PolicyStatement is the compliance-package view of an S3 bucket
// policy statement. It is structurally similar to the legacy shape
// (Sid / Effect / Action / Resource), but Principal and Condition are
// now backed by the typed shapes from internal/platform/providers/
// aws/s3/policy. The bridge keeps every public method consumer
// unchanged while routing the actual decode through the canonical
// s3/policy parser — see docs/sir-pending-discussion.md (Q1 = Bridge)
// for the design rationale.
//
// Tests construct PolicyStatement literals directly (see
// policy_helper_test.go), so the field shape is part of the public
// surface; field types changed but field names and meanings are
// preserved. The 13 control files in this package only invoke the
// methods below, never the struct literal, so they pick up the
// typed-internals win for free.
type PolicyStatement struct {
	Sid       string
	Effect    string
	Principal s3policy.NormalizedPrincipal
	Action    []string
	Resource  []string
	Condition s3policy.NormalizedCondition
}

// IsAllow reports whether this statement has Effect "Allow" (case-insensitive).
func (s PolicyStatement) IsAllow() bool {
	return strings.EqualFold(s.Effect, "Allow")
}

// IsDeny reports whether this statement has Effect "Deny" (case-insensitive).
func (s PolicyStatement) IsDeny() bool {
	return strings.EqualFold(s.Effect, "Deny")
}

// HasWildcardPrincipal reports whether the principal is "*" or
// includes "*" inside the AWS principal list.
//
// Reads the typed NormalizedPrincipal directly. The earlier shape
// type-asserted on `any`-typed Principal at every call site; the
// normalization at parse time made the field a single boolean check.
func (s PolicyStatement) HasWildcardPrincipal() bool {
	return s.Principal.Wildcard
}

// HasAction reports whether the statement includes the given action
// (case-insensitive).
func (s PolicyStatement) HasAction(action string) bool {
	lower := strings.ToLower(action)
	for _, a := range s.Action {
		if strings.ToLower(a) == lower {
			return true
		}
	}
	return false
}

// HasWildcardAction reports whether the statement includes "s3:*" or "*".
func (s PolicyStatement) HasWildcardAction() bool {
	for _, a := range s.Action {
		if a == "*" || strings.EqualFold(a, "s3:*") {
			return true
		}
	}
	return false
}

// ParsePolicyStatements extracts policy statements from a raw policy
// JSON string. Returns nil with no error when policyJSON is empty or
// not valid JSON — matches the legacy fail-soft contract every
// control file relies on.
//
// The parse is delegated to s3/policy.Parse so the typed
// NormalizedPrincipal and NormalizedCondition land directly on the
// returned PolicyStatement. The earlier shape carried its own
// raw-bytes parser (parseOneStatement) that decoded each field
// individually; deleting that duplicate is the entire point of
// the bridge.
func ParsePolicyStatements(policyJSON string) ([]PolicyStatement, error) {
	policyJSON = strings.TrimSpace(policyJSON)
	if policyJSON == "" {
		return nil, nil
	}
	doc, err := s3policy.Parse(policyJSON)
	if err != nil {
		// Fail-loud: a present-but-unparseable policy must NOT be treated as
		// "no statements" — that masks any public/over-broad grant the broken
		// JSON might contain. Propagate; callers flag the bucket as
		// "policy present but unparseable, cannot prove safe" rather than PASS.
		// (Empty / absent policy is handled above as nil,nil — that stays.)
		return nil, fmt.Errorf("parse bucket policy: %w", err)
	}
	stmts := doc.Statements()
	out := make([]PolicyStatement, 0, len(stmts))
	for i := range stmts {
		out = append(out, fromTypedStatement(&stmts[i]))
	}
	return out, nil
}

// fromTypedStatement copies the typed s3/policy.Statement fields into
// a compliance.PolicyStatement. Lives inside this package so the
// translation rule stays next to the type that depends on it; the
// inverse (compliance → s3/policy) doesn't exist because compliance
// is a downstream consumer, not a producer.
func fromTypedStatement(s *s3policy.Statement) PolicyStatement {
	return PolicyStatement{
		Sid:       s.Sid,
		Effect:    string(s.Effect),
		Principal: s.Principal,
		Action:    []string(s.Action),
		Resource:  []string(s.Resource),
		Condition: s.Condition,
	}
}

// IAM condition operators and keys used in policy guardrail detection.
const (
	condOpBool               = "Bool"
	condOpNumericGreaterThan = "NumericGreaterThan"
	condOpStringNotEquals    = "StringNotEquals"

	condKeySecureTransport = "aws:SecureTransport"
	condKeySignatureAge    = "s3:signatureAge"
	condKeyAuthType        = "s3:authType"
)

// IsDenyNonTLS reports whether this statement denies access when
// aws:SecureTransport is false (i.e. enforces TLS).
//
// Uses the typed Condition.Lookup. The legacy shape navigated an
// `any`-typed Condition map and tolerated both string("false") and
// bool(false) leaves; the parse-time coerceConditionValues already
// flattened both wire forms to the string "false", so the check
// here is a single string-equal comparison.
func (s PolicyStatement) IsDenyNonTLS() bool {
	if !s.IsDeny() {
		return false
	}
	values, ok := s.Condition.Lookup(condOpBool, condKeySecureTransport)
	if !ok {
		return false
	}
	for _, v := range values {
		if strings.EqualFold(strings.TrimSpace(v), "false") {
			return true
		}
	}
	return false
}

// HasSignatureAgeGuardrail reports whether this statement denies
// requests where s3:signatureAge exceeds a threshold (presigned URL
// age limit). Presence of the key is the gate — the threshold value
// itself isn't validated here because AWS treats any
// NumericGreaterThan as restrictive.
func (s PolicyStatement) HasSignatureAgeGuardrail() bool {
	if !s.IsDeny() {
		return false
	}
	_, ok := s.Condition.Lookup(condOpNumericGreaterThan, condKeySignatureAge)
	return ok
}

// HasAuthTypeGuardrail reports whether this statement denies requests
// where s3:authType is not REST-HEADER (blocks presigned URL access).
func (s PolicyStatement) HasAuthTypeGuardrail() bool {
	if !s.IsDeny() {
		return false
	}
	values, ok := s.Condition.Lookup(condOpStringNotEquals, condKeyAuthType)
	if !ok {
		return false
	}
	for _, v := range values {
		if strings.EqualFold(v, "REST-HEADER") {
			return true
		}
	}
	return false
}

// RestrictsPresignedURLAccess reports whether this statement constrains
// presigned URL usage via signature age limits or auth type requirements.
func (s PolicyStatement) RestrictsPresignedURLAccess() bool {
	return s.HasSignatureAgeGuardrail() || s.HasAuthTypeGuardrail()
}

// IsPublicListGrant reports whether this statement allows a wildcard
// principal to list bucket contents (s3:ListBucket). This enables full
// key enumeration, defeating any object-key obscurity approach.
func (s PolicyStatement) IsPublicListGrant() bool {
	return s.IsAllow() && s.HasWildcardPrincipal() && s.HasAction("s3:ListBucket")
}

// GrantsWildcardActions reports whether this statement allows wildcard
// actions (s3:* or *), granting more permissions than intended.
func (s PolicyStatement) GrantsWildcardActions() bool {
	return s.IsAllow() && s.HasWildcardAction()
}
