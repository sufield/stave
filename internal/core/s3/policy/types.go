package policy

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// Policy constants.
const (
	wildcard         = "*"
	s3Wildcard       = "s3:*"
	s3GlobalResource = "arn:aws:s3:::*"
)

// S3 action constants (lowercase for case-insensitive matching).
const (
	actionGetObject          = "s3:getobject"
	actionListBucket         = "s3:listbucket"
	actionListBucketVersions = "s3:listbucketversions"
	actionPutObject          = "s3:putobject"
	actionPutObjectACL       = "s3:putobjectacl"
	actionPutBucketPolicy    = "s3:putbucketpolicy"
	actionDeleteObject       = "s3:deleteobject"
	actionDeleteBucket       = "s3:deletebucket"
	actionPutBucketACL       = "s3:putbucketacl"
	actionGetBucketACL       = "s3:getbucketacl"
	actionGetObjectACL       = "s3:getobjectacl"
	actionPrefixGet          = "s3:get"
	actionPrefixList         = "s3:list"
	actionPrefixPut          = "s3:put"
	actionPrefixDelete       = "s3:delete"
)

// Condition keys and values.
const (
	condBool            = "Bool"
	condSecureTransport = "aws:SecureTransport"
	condValueFalse      = "false"
	principalAWS        = "AWS"
)

// Condition operator prefixes and suffixes.
const (
	condPrefixForAnyValue  = "foranyvalue:"
	condPrefixForAllValues = "forallvalues:"
	condSuffixIfExists     = "ifexists"
)

// Effect represents the Allow or Deny status of a policy statement.
type Effect string

const (
	EffectAllow Effect = "Allow"
	EffectDeny  Effect = "Deny"
)

// IsAllow reports whether the effect is Allow (case-insensitive).
func (e Effect) IsAllow() bool { return strings.EqualFold(string(e), "allow") }

// IsDeny reports whether the effect is Deny (case-insensitive).
func (e Effect) IsDeny() bool { return strings.EqualFold(string(e), "deny") }

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

// ConditionAnalysis contains the result of an AWS policy condition inspection.
type ConditionAnalysis struct {
	HasIPCondition  bool
	HasVPCCondition bool
	HasOrgCondition bool
	ConditionKeys   []string
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

// PrincipalScope determines the exposure level of the statement.
func (s Statement) PrincipalScope() kernel.PrincipalScope {
	return classifyPolicyPrincipalScope(s.decodeRaw(s.Principal))
}

// ConditionAnalysis extracts scoping information from the Condition block.
func (s Statement) ConditionAnalysis() ConditionAnalysis {
	return analyzeCondition(s.decodeRaw(s.Condition))
}

// IsPubliclyExposed reports whether this is an Allow statement with a public principal.
func (s Statement) IsPubliclyExposed() bool {
	return s.Effect.IsAllow() && s.PrincipalScope().IsPublic()
}

// HasWildcardActionsOnWildcardResources reports whether the statement
// grants all actions on all resources.
func (s Statement) HasWildcardActionsOnWildcardResources() bool {
	_, hasFullWildcardAction := s.ResolveActions()
	if !hasFullWildcardAction {
		return false
	}
	return hasWildcardResource([]string(s.Resource))
}

// EnforcesHTTPS reports whether this is a Deny statement requiring HTTPS.
func (s Statement) EnforcesHTTPS() bool {
	if !s.Effect.IsDeny() || !s.PrincipalScope().IsPublic() {
		return false
	}
	return hasSecureTransportCondition(s.Condition)
}

// PrincipalARNs extracts ARN strings from the Principal field.
func (s Statement) PrincipalARNs() []string {
	return extractPrincipalARNs(s.decodeRaw(s.Principal))
}

// HasWriteActions reports whether any action in the statement is a write action.
func (s Statement) HasWriteActions() bool {
	return slices.ContainsFunc([]string(s.Action), isWriteAction)
}

// decodeRaw unmarshals a json.RawMessage into any, used for Principal
// and Condition fields that have varying JSON shapes.
func (s Statement) decodeRaw(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var v any
	_ = json.Unmarshal(raw, &v)
	return v
}

// hasSecureTransportCondition checks if Condition contains
// Bool.aws:SecureTransport = false.
func hasSecureTransportCondition(condition json.RawMessage) bool {
	if len(condition) == 0 {
		return false
	}

	var cond map[string]map[string]any
	if err := json.Unmarshal(condition, &cond); err != nil {
		return false
	}

	boolCond, ok := cond[condBool]
	if !ok {
		return false
	}

	raw, ok := boolCond[condSecureTransport]
	if !ok {
		return false
	}

	switch v := raw.(type) {
	case string:
		return strings.EqualFold(strings.TrimSpace(v), condValueFalse)
	case bool:
		return !v
	default:
		return false
	}
}
