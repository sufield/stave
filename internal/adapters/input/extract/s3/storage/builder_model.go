package storage

func BuildModel(in BuildModelInput) S3StorageModel {
	bucket := in.Bucket

	access := in.Access

	model := S3StorageModel{
		Kind:       "bucket",
		ID:         bucket.Name.ModelID(),
		Name:       bucket.Name.Name(),
		Visibility: access.Visibility,
		ACL: ACLSummary{
			FullControlPublic:        access.ACLFullControl.FullControlPublic,
			FullControlAuthenticated: access.ACLFullControl.FullControlAuthenticated,
		},
		Controls: buildS3Controls(in),
		PrefixExposure: S3PrefixExposure{
			HasIdentityEvidence:   access.PrefixExposure.HasIdentityEvidence,
			HasResourceEvidence:   access.PrefixExposure.HasResourceEvidence,
			IdentityReadScopes:    access.PrefixExposure.IdentityReadScopes,
			IdentitySourceByScope: access.PrefixExposure.IdentitySourceByScope,
			IdentityReadBlocked:   access.PrefixExposure.IdentityReadBlocked,
			ResourceReadAll:       access.PrefixExposure.ResourceReadAll,
			ResourceReadBlocked:   access.PrefixExposure.ResourceReadBlocked,
		},
		Encryption: S3Encryption{
			AtRestEnabled:     bucket.Encryption != nil,
			Algorithm:         encryptionAlgorithmOrEmpty(bucket.Encryption),
			KMSKeyID:          encryptionKMSKeyOrEmpty(bucket.Encryption),
			InTransitEnforced: in.TransportEnforcesHTTPS,
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
		Access: CrossAccountSummary{
			ExternalAccounts:   access.CrossAccount.ExternalAccountARNs,
			ExternalAccountIDs: access.CrossAccount.ExternalAccountIDs,
			HasExternalAccess:  access.CrossAccount.HasExternalAccess,
			HasExternalWrite:   access.CrossAccount.HasExternalWrite,
			HasWildcardPolicy:  access.HasWildcardPolicy,
		},
		Policy: S3Policy{
			HasIPCondition:        access.NetworkScope.HasIPCondition,
			HasVPCCondition:       access.NetworkScope.HasVPCCondition,
			EffectiveNetworkScope: access.NetworkScope.EffectiveNetworkScope,
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
