package hipaa

import (
	"encoding/json"
	"strings"
)

// PolicyStatement is a minimal representation of an S3 bucket policy statement
// for control evaluation. It captures only the fields controls need.
type PolicyStatement struct {
	Sid       string   `json:"Sid,omitempty"`
	Effect    string   `json:"Effect"`
	Principal any      `json:"Principal"`
	Action    []string `json:"-"` // normalized from string or []string
	Resource  []string `json:"-"` // normalized from string or []string
	Condition any      `json:"Condition,omitempty"`
}

// IsAllow reports whether this statement has Effect "Allow" (case-insensitive).
func (s PolicyStatement) IsAllow() bool {
	return strings.EqualFold(s.Effect, "Allow")
}

// HasWildcardPrincipal reports whether the principal is "*" or includes "*".
func (s PolicyStatement) HasWildcardPrincipal() bool {
	switch p := s.Principal.(type) {
	case string:
		return p == "*"
	case map[string]any:
		for _, v := range p {
			if isWildcard(v) {
				return true
			}
		}
	}
	return false
}

// HasAction reports whether the statement includes the given action (case-insensitive).
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

// ParsePolicyStatements extracts policy statements from a raw policy JSON string.
// Returns nil with no error if policyJSON is empty or not valid JSON.
func ParsePolicyStatements(policyJSON string) ([]PolicyStatement, error) {
	policyJSON = strings.TrimSpace(policyJSON)
	if policyJSON == "" {
		return nil, nil
	}

	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		return nil, nil // unparseable policy treated as empty
	}
	if doc.Statement == nil {
		return nil, nil
	}

	// Statement can be a single object or an array.
	var stmts []json.RawMessage
	if len(doc.Statement) > 0 && doc.Statement[0] == '[' {
		if err := json.Unmarshal(doc.Statement, &stmts); err != nil {
			return nil, nil
		}
	} else {
		stmts = []json.RawMessage{doc.Statement}
	}

	out := make([]PolicyStatement, 0, len(stmts))
	for _, raw := range stmts {
		ps, err := parseOneStatement(raw)
		if err != nil {
			continue
		}
		out = append(out, ps)
	}
	return out, nil
}

func parseOneStatement(raw json.RawMessage) (PolicyStatement, error) {
	// Use a struct with json.RawMessage for polymorphic fields.
	var s struct {
		Sid       string          `json:"Sid"`
		Effect    string          `json:"Effect"`
		Principal json.RawMessage `json:"Principal"`
		Action    json.RawMessage `json:"Action"`
		Resource  json.RawMessage `json:"Resource"`
		Condition json.RawMessage `json:"Condition"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return PolicyStatement{}, err
	}

	var principal any
	if s.Principal != nil {
		_ = json.Unmarshal(s.Principal, &principal)
	}

	var condition any
	if s.Condition != nil {
		_ = json.Unmarshal(s.Condition, &condition)
	}

	return PolicyStatement{
		Sid:       s.Sid,
		Effect:    s.Effect,
		Principal: principal,
		Action:    normalizeStringList(s.Action),
		Resource:  normalizeStringList(s.Resource),
		Condition: condition,
	}, nil
}

// normalizeStringList handles the AWS "string or []string" JSON pattern.
func normalizeStringList(raw json.RawMessage) []string {
	if raw == nil {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	return nil
}

// IsDenyNonTLS reports whether this statement denies access when
// aws:SecureTransport is false (i.e. enforces TLS).
func (s PolicyStatement) IsDenyNonTLS() bool {
	if !s.IsDeny() {
		return false
	}
	cond, ok := s.Condition.(map[string]any)
	if !ok {
		return false
	}
	boolBlock, ok := cond["Bool"].(map[string]any)
	if !ok {
		return false
	}
	val, ok := boolBlock["aws:SecureTransport"]
	if !ok {
		return false
	}
	switch v := val.(type) {
	case string:
		return v == "false"
	case bool:
		return !v
	}
	return false
}

// IsDeny reports whether this statement has Effect "Deny" (case-insensitive).
func (s PolicyStatement) IsDeny() bool {
	return strings.EqualFold(s.Effect, "Deny")
}

// HasSignatureAgeGuardrail reports whether this statement denies requests
// where s3:signatureAge exceeds a threshold (presigned URL age limit).
func (s PolicyStatement) HasSignatureAgeGuardrail() bool {
	if !s.IsDeny() {
		return false
	}
	cond, ok := s.Condition.(map[string]any)
	if !ok {
		return false
	}
	block, ok := cond["NumericGreaterThan"].(map[string]any)
	if !ok {
		return false
	}
	_, ok = block["s3:signatureAge"]
	return ok
}

// HasAuthTypeGuardrail reports whether this statement denies requests
// where s3:authType is not REST-HEADER (blocks presigned URL access).
func (s PolicyStatement) HasAuthTypeGuardrail() bool {
	if !s.IsDeny() {
		return false
	}
	cond, ok := s.Condition.(map[string]any)
	if !ok {
		return false
	}
	block, ok := cond["StringNotEquals"].(map[string]any)
	if !ok {
		return false
	}
	val, ok := block["s3:authType"]
	if !ok {
		return false
	}
	str, ok := val.(string)
	return ok && strings.EqualFold(str, "REST-HEADER")
}

func isWildcard(v any) bool {
	switch val := v.(type) {
	case string:
		return val == "*"
	case []any:
		for _, item := range val {
			if s, ok := item.(string); ok && s == "*" {
				return true
			}
		}
	}
	return false
}
