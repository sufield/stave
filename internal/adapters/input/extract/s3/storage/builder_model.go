package storage

import "fmt"

func BuildModel(in BuildModelInput) S3StorageModel {
	bucket := in.Bucket

	model := S3StorageModel{
		Kind:       "bucket",
		ID:         fmt.Sprintf("aws:s3:::%s", bucket.Name),
		Name:       bucket.Name,
		Visibility: in.Visibility,
		ACL: ACLSummary{
			FullControlPublic:        in.Visibility.HasFullControlPublic,
			FullControlAuthenticated: in.Visibility.HasFullControlAuthenticatedOnly,
		},
		Controls: buildS3Controls(in),
		PrefixExposure: buildPrefixExposureModel(prefixExposureModelInput{
			PolicyJSON:     bucket.PolicyJSON,
			ACLAnalysis:    in.Analysis.ACL,
			HasACLAnalysis: in.Analysis.HasACL,
			PolicyBlocked:  in.Visibility.PolicyExposureBlocked,
			ACLBlocked:     in.Visibility.ACLExposureBlocked,
		}),
		Encryption: S3Encryption{
			AtRestEnabled:     bucket.Encryption != nil,
			Algorithm:         encryptionAlgorithmOrEmpty(bucket.Encryption),
			KMSKeyID:          encryptionKMSKeyOrEmpty(bucket.Encryption),
			InTransitEnforced: in.Analysis.Transport.EnforcesHTTPS,
		},
		Versioning: S3Versioning{
			Enabled:          bucket.Versioning != nil && bucket.Versioning.Status == VersioningEnabled,
			MFADeleteEnabled: bucket.Versioning != nil && bucket.Versioning.MFADelete == MFADeleteEnabled,
		},
		Logging: S3Logging{
			Enabled:      bucket.Logging != nil,
			TargetBucket: loggingTargetBucket(bucket.Logging),
			TargetPrefix: loggingTargetPrefix(bucket.Logging),
		},
		Access: S3Access{
			ExternalAccounts:   in.Analysis.CrossAccount.ExternalAccountARNs,
			ExternalAccountIDs: in.Analysis.CrossAccount.ExternalAccountIDs,
			HasExternalAccess:  in.Analysis.CrossAccount.HasExternalAccess,
			HasExternalWrite:   in.Analysis.CrossAccount.HasExternalWrite,
			HasWildcardPolicy:  in.Analysis.Policy.HasWildcardActions,
		},
		Policy: S3Policy{
			HasIPCondition:        in.Analysis.Policy.HasIPCondition,
			HasVPCCondition:       in.Analysis.Policy.HasVPCCondition,
			EffectiveNetworkScope: in.Analysis.Policy.EffectiveNetworkScope,
		},
		Website:    websiteFromBucket(bucket),
		Lifecycle:  bucket.Lifecycle.Canonical(),
		ObjectLock: bucket.ObjectLock.Canonical(),
	}
	if len(bucket.Tags) > 0 {
		model.Tags = bucket.Tags
	}
	return model
}

func websiteFromBucket(bucket *S3Bucket) *S3Website {
	if bucket.Website == nil {
		return nil
	}
	return &S3Website{Enabled: true}
}

func encryptionAlgorithmOrEmpty(enc *EncryptionConfig) string {
	if enc == nil {
		return ""
	}
	return string(enc.Algorithm)
}

func encryptionKMSKeyOrEmpty(enc *EncryptionConfig) string {
	if enc == nil {
		return ""
	}
	return enc.KMSKeyARN
}

func loggingTargetBucket(lc *LoggingConfig) string {
	if lc == nil {
		return ""
	}
	return lc.TargetBucket
}

func loggingTargetPrefix(lc *LoggingConfig) string {
	if lc == nil {
		return ""
	}
	return lc.TargetPrefix
}
