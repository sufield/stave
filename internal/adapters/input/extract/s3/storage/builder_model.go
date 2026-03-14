package storage

func BuildModel(in BuildModelInput) S3StorageModel {
	bucket := in.Bucket

	access := in.Access

	model := S3StorageModel{
		Kind: "bucket",
		ID:   bucket.Name.ModelID(),
		Name: bucket.Name.Name(),
		Access: S3AccessModel{
			Scope:         access.Scope,
			TrustBoundary: access.TrustBoundary,
			// Effective permissions
			PublicRead:   access.Visibility.PublicRead,
			PublicList:   access.Visibility.PublicList,
			PublicWrite:  access.Visibility.PublicWrite,
			PublicDelete: access.Visibility.PublicDelete,
			PublicAdmin:  access.Visibility.PublicAdmin,
			// Origin signals
			ReadViaIdentity:  access.Visibility.ReadViaIdentity,
			ReadViaResource:  access.Visibility.ReadViaResource,
			ListViaIdentity:  access.Visibility.ListViaIdentity,
			WriteViaResource: access.Visibility.WriteViaResource,
			AdminViaResource: access.Visibility.AdminViaResource,
			// Authenticated scope
			AuthenticatedRead:  access.Visibility.AuthenticatedRead,
			AuthenticatedWrite: access.Visibility.AuthenticatedWrite,
			AuthenticatedAdmin: access.Visibility.AuthenticatedAdmin,
			// Latent signals
			LatentPublicRead: access.Visibility.LatentPublicRead,
			LatentPublicList: access.Visibility.LatentPublicList,
			// ACL full-control grants
			FullControlPublic:        access.ACLFullControl.FullControlPublic,
			FullControlAuthenticated: access.ACLFullControl.FullControlAuthenticated,
			// Cross-account
			ExternalAccounts:   access.CrossAccount.ExternalAccountARNs,
			ExternalAccountIDs: access.CrossAccount.ExternalAccountIDs,
			HasExternalAccess:  access.CrossAccount.HasExternalAccess,
			HasExternalWrite:   access.CrossAccount.HasExternalWrite,
			HasWildcardPolicy:  access.HasWildcardPolicy,
			// Network scope
			HasIPCondition:        access.NetworkScope.HasIPCondition,
			HasVPCCondition:       access.NetworkScope.HasVPCCondition,
			EffectiveNetworkScope: access.NetworkScope.EffectiveNetworkScope,
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
