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
//
// Action and Resource carry the AWS "string or []string" wire shape
// after normalization — UnmarshalJSON handles both forms. Condition
// is left as `any` because no IAM-side consumer reads it today; see
// docs/sir-pending-discussion.md (Q2) for the typed-condition
// follow-up. The earlier shape decoded each field through an
// intermediate raw-bytes round trip inside ParsePolicyDocument; the
// custom Unmarshal here removes that hop so the parse boundary is
// the only decode point.
type Statement struct {
	Sid       string   `json:"Sid"`
	Effect    Effect   `json:"Effect"`
	Action    []string // normalized from string or []string by UnmarshalJSON
	Resource  []string // normalized from string or []string by UnmarshalJSON
	Condition any      `json:"Condition"`
}

// UnmarshalJSON decodes a statement, normalizing Action and Resource
// to []string regardless of whether the wire form is a single string
// or an array. Returning an error here surfaces a malformed statement
// to ParsePolicyDocument's per-statement error wrap so the caller
// gets a precise diagnostic instead of a cryptic top-level decode
// failure.
func (s *Statement) UnmarshalJSON(data []byte) error {
	// Use an alias type to avoid recursion into this UnmarshalJSON.
	// Action and Resource are decoded into a tolerant `any` then
	// passed through normalizeStringOrAny, which mirrors the AWS
	// "string or []string" tolerance the legacy normalizeStringOrList
	// implemented for the raw-bytes form.
	type aux struct {
		Sid       string `json:"Sid"`
		Effect    Effect `json:"Effect"`
		Action    any    `json:"Action"`
		Resource  any    `json:"Resource"`
		Condition any    `json:"Condition"`
	}
	var a aux
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	actions, err := normalizeStringOrAny(a.Action)
	if err != nil {
		return fmt.Errorf("decode Action field: %w", err)
	}
	resources, err := normalizeStringOrAny(a.Resource)
	if err != nil {
		return fmt.Errorf("decode Resource field: %w", err)
	}
	s.Sid = a.Sid
	s.Effect = a.Effect
	s.Action = actions
	s.Resource = resources
	s.Condition = a.Condition
	return nil
}

// PolicyDocument is a parsed IAM policy document.
type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// ParsePolicyDocument parses a JSON IAM policy document string into
// typed statements. Returns an error if the JSON is invalid. Empty
// documents produce zero statements.
//
// Decoding is single-pass: the per-statement polymorphism for Action
// and Resource is handled by Statement.UnmarshalJSON, so this
// function no longer needs the intermediate raw-bytes hop the
// earlier shape ran (one outer Unmarshal into raw-statement bytes,
// then a second per-statement Unmarshal). Decoding once means a
// future migration to the SIR builder can hand a single typed
// PolicyDocument straight to the export pipeline.
func ParsePolicyDocument(raw string) (PolicyDocument, error) {
	if strings.TrimSpace(raw) == "" {
		return PolicyDocument{}, nil
	}
	var doc PolicyDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return PolicyDocument{}, fmt.Errorf("parse policy document: %w", err)
	}
	return doc, nil
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

// normalizeStringOrAny handles IAM's "string or []string" pattern
// against an already-decoded `any`. Mirrors the legacy
// normalizeStringOrList shape (which operated on raw bytes) so the
// behaviour is preserved across the parse-boundary refactor: a bare
// string becomes a one-element slice, an array of strings round-trips,
// nil and "null" produce nil, and any other type is rejected with a
// descriptive error.
func normalizeStringOrAny(v any) ([]string, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{x}, nil
	case []any:
		out := make([]string, 0, len(x))
		for i, item := range x {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("element %d: expected string, got %T", i, item)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected string or []string, got %T", v)
	}
}
