package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// Effect represents the Allow or Deny status of a policy statement.
type Effect string

const (
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

// BucketPolicy represents an S3 bucket policy document.
type BucketPolicy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Statement represents a single statement in a bucket policy.
type Statement struct {
	Sid       string          `json:"Sid,omitempty"`
	Effect    Effect          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Action    StringList      `json:"Action"`
	Resource  StringList      `json:"Resource"`
	Condition json.RawMessage `json:"Condition,omitempty"`
}

// StatementID returns a kernel-compatible ID based on Sid or index.
func (s Statement) StatementID(index int) kernel.StatementID {
	if s.Sid != "" {
		return kernel.StatementID(fmt.Sprintf("sid:%s", s.Sid))
	}
	return kernel.StatementID(fmt.Sprintf("idx:%d", index))
}

// NormalizeStringOrSlice handles the AWS JSON polymorphism of single string vs array.
func NormalizeStringOrSlice(v any) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []string:
		return val
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
