package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// Effect represents the Allow or Deny status of a policy statement.
type Effect string

// EffectAllow and related constants.
const (
	// EffectAllow constants.
	EffectAllow Effect = "Allow"
	EffectDeny  Effect = "Deny"
)

// IsAllow reports whether the effect is Allow (case-insensitive).
func (e Effect) IsAllow() bool { return strings.EqualFold(string(e), string(EffectAllow)) }

// IsDeny reports whether the effect is Deny (case-insensitive).
func (e Effect) IsDeny() bool { return strings.EqualFold(string(e), string(EffectDeny)) }

// String implements fmt.Stringer.
func (e Effect) String() string { return string(e) }

// StringList handles the AWS "string or []string" JSON polymorphic pattern.
type StringList []string

// UnmarshalJSON handles both `"value"` and `["value"]` forms.
func (s *StringList) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		*s = StringList{str}
		return nil
	}

	var slice []string
	if err := json.Unmarshal(data, &slice); err != nil {
		return err
	}
	*s = slice
	return nil
}

// BucketPolicy represents an S3 bucket policy document. Statement
// uses a custom UnmarshalJSON to absorb the AWS wire polymorphism:
// Statement may be either a single object or an array of objects.
// The legacy compliance parser handled this with a hand-rolled
// raw-bytes probe; the typed unmarshal below makes the polymorphism
// part of the Document contract so every consumer
// (s3/policy.Document.Assess, the compliance bridge, future SIR
// builders) sees the same flattened []Statement view.
type BucketPolicy struct {
	Version   string              `json:"Version"`
	Statement bucketPolicyStmtSet `json:"Statement"`
}

// bucketPolicyStmtSet is the alias type that owns the
// "single object OR array" UnmarshalJSON. Defined as a separate
// type so the custom Unmarshal does not fight the default array
// decoding for []Statement when consumers want the typed field
// directly. BucketPolicy.Statement remains operationally equivalent
// to []Statement after decoding.
type bucketPolicyStmtSet []Statement

// UnmarshalJSON accepts either a JSON array of statement objects or
// a single statement object. AWS allows both forms in the same
// policy field; rejecting the single-object form would break every
// hand-written bucket policy that only has one statement.
func (s *bucketPolicyStmtSet) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*s = nil
		return nil
	}
	// Probe the first non-whitespace byte: '[' is array, '{' is
	// single object. This matches the legacy compliance parser's
	// polymorphism check without re-introducing raw-bytes fields in
	// any struct — the local []byte stays inside this method.
	for _, b := range data {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		if b == '[' {
			var arr []Statement
			if err := json.Unmarshal(data, &arr); err != nil {
				return err
			}
			*s = arr
			return nil
		}
		break
	}
	var single Statement
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	*s = []Statement{single}
	return nil
}

// Statement represents a single statement in a bucket policy.
//
// Principal and Condition are decoded into typed structures at parse
// time (see NormalizedPrincipal / NormalizedCondition). The earlier
// shape carried raw JSON here, forcing every consumer to re-decode
// the same bytes on each access — costly under repeated evaluation
// and a barrier to SIR export, where the same fact would otherwise
// leak raw JSON into the canonical contract. Front-loading the
// decode lets every downstream method operate on field access
// instead of type-assertions.
type Statement struct {
	Sid       string              `json:"Sid,omitempty"`
	Effect    Effect              `json:"Effect"`
	Principal NormalizedPrincipal `json:"Principal"`
	Action    StringList          `json:"Action"`
	Resource  StringList          `json:"Resource"`
	Condition NormalizedCondition `json:"Condition,omitempty"`
}

// StatementID returns a kernel-compatible ID based on Sid or index.
func (s Statement) StatementID(index int) kernel.StatementID {
	if s.Sid != "" {
		return kernel.StatementID("sid:" + s.Sid)
	}
	return kernel.StatementID(fmt.Sprintf("idx:%d", index))
}

// NormalizeStringOrSlice handles the AWS JSON polymorphism of single string vs array.
func NormalizeStringOrSlice(v any) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return []string{val}
	case []string:
		return val
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if item != nil {
				if s, ok := item.(string); ok {
					out = append(out, s)
				} else {
					out = append(out, fmt.Sprint(item))
				}
			}
		}
		return out
	default:
		return []string{fmt.Sprint(v)}
	}
}
