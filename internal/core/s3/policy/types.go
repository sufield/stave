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

// ConditionKey is a typed string identifying an AWS policy condition key
// (e.g., "aws:SourceIp", "aws:sourceVpc").
type ConditionKey string

// Well-known AWS condition keys.
const (
	CondKeySourceIP       ConditionKey = "aws:SourceIp"
	CondKeySourceVPC      ConditionKey = "aws:sourceVpc"
	CondKeyPrincipalOrgID ConditionKey = "aws:PrincipalOrgID"
)

// ConditionAnalysis contains the result of an AWS policy condition inspection.
type ConditionAnalysis struct {
	HasIPCondition  bool
	HasVPCCondition bool
	HasOrgCondition bool
	ConditionKeys   []ConditionKey
}

// IsNetworkScoped reports whether any network-scoping condition is present.
func (c ConditionAnalysis) IsNetworkScoped() bool {
	return c.HasIPCondition || c.HasVPCCondition || c.HasOrgCondition
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
