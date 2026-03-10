package storage

import s3acl "github.com/sufield/stave/internal/adapters/input/extract/s3/acl"

// AWSS3Evidence is the vendor-specific S3 evidence contract.
type AWSS3Evidence struct {
	ARN        string            `json:"arn,omitempty"`
	Policy     string            `json:"policy,omitempty"`
	Grants     []s3acl.Grant     `json:"acl_grants,omitempty"`
	PAB        *PABStatus        `json:"public_access_block,omitempty"`
	Security   SecurityEvidence  `json:"security"`
	Operations OperationEvidence `json:"operations"`
}

// SecurityEvidence groups security-related sub-evidence.
type SecurityEvidence struct {
	Encryption *EncryptionEvidence `json:"encryption,omitempty"`
	ObjectLock *ObjectLockEvidence `json:"object_lock,omitempty"`
}

// OperationEvidence groups operational sub-evidence.
type OperationEvidence struct {
	Versioning *VersioningEvidence `json:"versioning,omitempty"`
	Logging    *LoggingEvidence    `json:"logging,omitempty"`
	Lifecycle  *LifecycleEvidence  `json:"lifecycle,omitempty"`
}

type EncryptionEvidence struct {
	Algorithm string `json:"algorithm"`
	KMSKeyARN string `json:"kms_key_arn,omitempty"`
}

type VersioningEvidence struct {
	Status    string `json:"status"`
	MFADelete string `json:"mfa_delete,omitempty"`
}

type LoggingEvidence struct {
	Enabled      bool   `json:"enabled"`
	TargetBucket string `json:"target_bucket,omitempty"`
	TargetPrefix string `json:"target_prefix,omitempty"`
}

type LifecycleEvidence struct {
	RuleCount int `json:"rule_count"`
}

type ObjectLockEvidence struct {
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode,omitempty"`
	RetentionDays int    `json:"retention_days,omitempty"`
}

type SourceEvidence struct {
	PolicyPublicStatements []string `json:"policy_public_statements,omitempty"`
	ACLPublicGrantees      []string `json:"acl_public_grantees,omitempty"`
}

func NewEncryptionEvidence(e *EncryptionConfig) *EncryptionEvidence {
	if e == nil || e.Algorithm == "" {
		return nil
	}
	return &EncryptionEvidence{
		Algorithm: string(e.Algorithm),
		KMSKeyARN: e.KMSKeyARN,
	}
}

func NewVersioningEvidence(v *VersioningConfig) *VersioningEvidence {
	if v == nil || v.Status == "" {
		return nil
	}
	return &VersioningEvidence{
		Status:    string(v.Status),
		MFADelete: string(v.MFADelete),
	}
}

func NewLoggingEvidence(l *LoggingConfig) *LoggingEvidence {
	if l == nil {
		return nil
	}
	return &LoggingEvidence{
		Enabled:      true,
		TargetBucket: l.TargetBucket,
		TargetPrefix: l.TargetPrefix,
	}
}

func NewLifecycleEvidence(l *LifecycleConfig) *LifecycleEvidence {
	if l == nil || !l.RulesConfigured {
		return nil
	}
	return &LifecycleEvidence{RuleCount: l.RuleCount}
}

func NewObjectLockEvidence(o *ObjectLockConfig) *ObjectLockEvidence {
	if o == nil || !o.Enabled {
		return nil
	}
	return &ObjectLockEvidence{
		Enabled:       true,
		Mode:          string(o.Mode),
		RetentionDays: o.RetentionDays,
	}
}

func BuildSourceEvidence(analysis S3AnalysisResult) *SourceEvidence {
	evidence := SourceEvidence{
		PolicyPublicStatements: analysis.Policy.PublicStatements,
		ACLPublicGrantees:      analysis.ACL.PublicGrantees,
	}
	if len(evidence.PolicyPublicStatements) == 0 && len(evidence.ACLPublicGrantees) == 0 {
		return nil
	}
	return &evidence
}

func BuildAWSS3Evidence(bucket *S3Bucket, analysis S3AnalysisResult) AWSS3Evidence {
	return AWSS3Evidence{
		ARN:    bucket.ARN,
		Policy: bucket.PolicyJSON,
		Grants: bucket.ACLGrants,
		PAB:    NewPABStatus(bucket.PublicAccessBlock),
		Security: SecurityEvidence{
			Encryption: NewEncryptionEvidence(bucket.Encryption),
			ObjectLock: NewObjectLockEvidence(bucket.ObjectLock),
		},
		Operations: OperationEvidence{
			Versioning: NewVersioningEvidence(bucket.Versioning),
			Logging:    NewLoggingEvidence(bucket.Logging),
			Lifecycle:  NewLifecycleEvidence(bucket.Lifecycle),
		},
	}
}
