// Package iam provides IAM policy resolution for computing net effective
// permissions from multiple policy layers.
package iam

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Effect is the effect of a policy statement (Allow or Deny).
type Effect string

const (
	EffectAllow Effect = "Allow"
	EffectDeny  Effect = "Deny"
)

// Statement is a single statement from an IAM policy document.
type Statement struct {
	Sid       string   `json:"Sid"`
	Effect    Effect   `json:"Effect"`
	Action    []string // normalized from string or []string
	Resource  []string // normalized from string or []string
	Condition any      `json:"Condition"`
}

// PolicyDocument is a parsed IAM policy document.
type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// ParsePolicyDocument parses a JSON IAM policy document string into typed
// statements. Returns an error if the JSON is invalid. Empty documents
// produce zero statements.
func ParsePolicyDocument(raw string) (PolicyDocument, error) {
	if strings.TrimSpace(raw) == "" {
		return PolicyDocument{}, nil
	}

	// Use raw JSON parsing to handle Action/Resource being string or []string.
	var doc struct {
		Version   string            `json:"Version"`
		Statement []json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return PolicyDocument{}, fmt.Errorf("parse policy document: %w", err)
	}

	stmts := make([]Statement, 0, len(doc.Statement))
	for i, rawStmt := range doc.Statement {
		var s struct {
			Sid       string          `json:"Sid"`
			Effect    Effect          `json:"Effect"`
			Action    json.RawMessage `json:"Action"`
			Resource  json.RawMessage `json:"Resource"`
			Condition any             `json:"Condition"`
		}
		if err := json.Unmarshal(rawStmt, &s); err != nil {
			return PolicyDocument{}, fmt.Errorf("parse statement %d: %w", i, err)
		}

		actions, err := normalizeStringOrList(s.Action)
		if err != nil {
			return PolicyDocument{}, fmt.Errorf("parse statement %d Action: %w", i, err)
		}
		resources, err := normalizeStringOrList(s.Resource)
		if err != nil {
			return PolicyDocument{}, fmt.Errorf("parse statement %d Resource: %w", i, err)
		}

		stmts = append(stmts, Statement{
			Sid:       s.Sid,
			Effect:    s.Effect,
			Action:    actions,
			Resource:  resources,
			Condition: s.Condition,
		})
	}

	return PolicyDocument{
		Version:   doc.Version,
		Statement: stmts,
	}, nil
}

// Allows returns all Allow statements in the document.
func (d PolicyDocument) Allows() []Statement {
	var out []Statement
	for _, s := range d.Statement {
		if s.Effect == EffectAllow {
			out = append(out, s)
		}
	}
	return out
}

// Denies returns all Deny statements in the document.
func (d PolicyDocument) Denies() []Statement {
	var out []Statement
	for _, s := range d.Statement {
		if s.Effect == EffectDeny {
			out = append(out, s)
		}
	}
	return out
}

// normalizeStringOrList handles IAM's pattern where Action and Resource
// can be either a single string or an array of strings.
func normalizeStringOrList(raw json.RawMessage) ([]string, error) {
	if raw == nil || string(raw) == "null" {
		return nil, nil
	}

	// Try string first.
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}, nil
	}

	// Try array.
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("expected string or []string from %s: %w", raw, err)
	}
	return list, nil
}
