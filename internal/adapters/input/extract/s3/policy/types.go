package policy

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/sufield/stave/internal/domain/kernel"
)

const (
	policyWildcard         = "*"
	policyS3Wildcard       = "s3:*"
	policyS3GlobalResource = "arn:aws:s3:::*"

	policyActionGetObject          = "s3:getobject"
	policyActionListBucket         = "s3:listbucket"
	policyActionListBucketVersions = "s3:listbucketversions"
	policyActionPutObject          = "s3:putobject"
	policyActionPutObjectACL       = "s3:putobjectacl"
	policyActionPutBucketPolicy    = "s3:putbucketpolicy"
	policyActionDeleteObject       = "s3:deleteobject"
	policyActionDeleteBucket       = "s3:deletebucket"
	policyActionPutBucketACL       = "s3:putbucketacl"
	policyActionGetBucketACL       = "s3:getbucketacl"
	policyActionGetObjectACL       = "s3:getobjectacl"
	policyActionPrefixGet          = "s3:get"
	policyActionPrefixList         = "s3:list"
	policyActionPrefixPut          = "s3:put"
	policyActionPrefixDelete       = "s3:delete"

	policyCondBool            = "Bool"
	policyCondSecureTransport = "aws:SecureTransport"
	policyCondSecureFalse     = "false"
	policyPrincipalAWS        = "AWS"

	policyScopePublic        = "public"
	policyScopeVPCRestricted = "vpc-restricted"
	policyScopeIPRestricted  = "ip-restricted"
	policyScopeOrgRestricted = "org-restricted"

	conditionPrefixForAnyValue = "foranyvalue:"
	conditionPrefixForAllValue = "forallvalues:"
	conditionSuffixIfExists    = "ifexists"
)

// Effect prevents invalid effect strings in policy statements.
type Effect string

const (
	EffectAllow Effect = "Allow"
	EffectDeny  Effect = "Deny"
)

func (e Effect) IsAllow() bool {
	return strings.EqualFold(string(e), "allow")
}

func (e Effect) IsDeny() bool {
	return strings.EqualFold(string(e), "deny")
}

// StringList handles the AWS "string or []string" JSON pattern.
type StringList []string

func (s *StringList) UnmarshalJSON(data []byte) error {
	// Try single string first.
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = StringList{single}
		return nil
	}

	// Otherwise decode as []string.
	var slice []string
	if err := json.Unmarshal(data, &slice); err != nil {
		return err
	}
	*s = slice
	return nil
}

// Analysis contains the analysis results of an S3 bucket policy.
type Analysis struct {
	AllowsPublicRead      bool
	AllowsPublicList      bool
	AllowsPublicWrite     bool
	AllowsPublicDelete    bool
	HasWildcardActions    bool
	PublicStatements      []kernel.StatementID // Statement IDs or indices that grant public access
	HasNetworkCondition   bool     // any statement with Principal:* also has IP/VPC/Org condition
	HasIPCondition        bool     // any public-principal statement has IP condition
	HasVPCCondition       bool     // any public-principal statement has VPC condition
	EffectiveNetworkScope string   // "public", "vpc-restricted", "ip-restricted", "org-restricted", or ""

	// Authenticated-only principal access (any AWS account, not anonymous)
	AllowsAuthenticatedRead  bool
	AllowsAuthenticatedList  bool
	AllowsAuthenticatedWrite bool

	// ACL-specific actions via bucket policy
	AllowsPublicACLWrite        bool // s3:PutBucketAcl or s3:PutObjectAcl to public principal
	AllowsPublicACLRead         bool // s3:GetBucketAcl or s3:GetObjectAcl to public principal
	AllowsAuthenticatedACLWrite bool // s3:PutBucketAcl or s3:PutObjectAcl to authenticated principal
	AllowsAuthenticatedACLRead  bool // s3:GetBucketAcl or s3:GetObjectAcl to authenticated principal
}

// ConditionAnalysis contains the analysis of AWS policy condition keys.
type ConditionAnalysis struct {
	HasIPCondition  bool
	HasVPCCondition bool
	HasOrgCondition bool
	ConditionKeys   []string // all condition keys found
}

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

func (s Statement) principalAny() any {
	if len(s.Principal) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(s.Principal, &v); err != nil {
		return nil
	}
	return v
}

func (s Statement) conditionAny() any {
	if len(s.Condition) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(s.Condition, &v); err != nil {
		return nil
	}
	return v
}

func (s Statement) IsAllow() bool {
	return s.Effect.IsAllow()
}

func (s Statement) IsDeny() bool {
	return s.Effect.IsDeny()
}

func (s Statement) ID(index int) kernel.StatementID {
	if s.Sid != "" {
		return kernel.StatementID("sid:" + s.Sid)
	}
	return kernel.StatementID("idx:" + strconv.Itoa(index))
}

func (s Statement) PrincipalScope() kernel.PrincipalScope {
	return classifyPolicyPrincipalScope(s.principalAny())
}

func (s Statement) ConditionAnalysis() ConditionAnalysis {
	return analyzeCondition(s.conditionAny())
}

func (s Statement) IsPubliclyExposed() bool {
	return s.IsAllow() && s.PrincipalScope().IsPublic()
}

func (s Statement) HasWildcardActionsOnWildcardResources() bool {
	_, hasFullWildcardAction := s.ResolveActions()
	if !hasFullWildcardAction {
		return false
	}
	return hasWildcardResource([]string(s.Resource))
}

func (s Statement) EnforcesHTTPS() bool {
	if !s.IsDeny() || !s.PrincipalScope().IsPublic() {
		return false
	}
	return hasSecureTransportCondition(s.Condition)
}

// hasSecureTransportCondition checks if Condition contains Bool.aws:SecureTransport = false.
func hasSecureTransportCondition(condition json.RawMessage) bool {
	if len(condition) == 0 {
		return false
	}

	var cond map[string]map[string]any
	if err := json.Unmarshal(condition, &cond); err != nil {
		return false
	}

	boolCond, ok := cond[policyCondBool]
	if !ok {
		return false
	}

	raw, ok := boolCond[policyCondSecureTransport]
	if !ok {
		return false
	}

	switch v := raw.(type) {
	case string:
		return strings.EqualFold(strings.TrimSpace(v), policyCondSecureFalse)
	case bool:
		return !v
	default:
		return false
	}
}

func (s Statement) PrincipalARNs() []string {
	return extractPrincipalARNs(s.principalAny())
}

func (s Statement) HasWriteActions() bool {
	return slices.ContainsFunc([]string(s.Action), isWriteAction)
}

// TransportEncryptionAnalysis contains the analysis of transport encryption enforcement.
type TransportEncryptionAnalysis struct {
	EnforcesHTTPS bool
}

// CrossAccountAnalysis contains the analysis of cross-account access in a bucket policy.
type CrossAccountAnalysis struct {
	ExternalAccountARNs []string
	ExternalAccountIDs  []string
	HasExternalAccess   bool
	HasExternalWrite    bool
}
