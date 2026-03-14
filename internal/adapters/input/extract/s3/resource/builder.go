package resource

import (
	s3acl "github.com/sufield/stave/internal/adapters/input/extract/s3/acl"
	s3policy "github.com/sufield/stave/internal/adapters/input/extract/s3/policy"
	s3storage "github.com/sufield/stave/internal/adapters/input/extract/s3/storage"
	"github.com/sufield/stave/internal/domain/asset"
	s3exposure "github.com/sufield/stave/internal/domain/evaluation/exposure"
)

// BuildBucketAsset converts a bucket model into a normalized asset.Asset.
func BuildBucketAsset(bucket *s3storage.S3Bucket, accountPAB *s3storage.PublicAccessBlock) asset.Asset {
	analysis := bucket.Analyze()
	effectivePAB := computeEffectivePAB(accountPAB, bucket.PublicAccessBlock)

	gov := ToGovernanceOverrides(effectivePAB)
	access := s3exposure.ResolveBucketAccess(s3exposure.BucketAccessInput{
		Identity:          ToIdentityVisibility(analysis.Policy),
		Resource:          ToResourceVisibility(analysis.ACL),
		Gov:               gov,
		CrossAccount:      toCrossAccountAccess(analysis.CrossAccount),
		NetworkScope:      toNetworkScopeAccess(analysis.Policy),
		ACLFullControl:    toACLFullControlAccess(analysis.ACL),
		PrefixExposure:    toPrefixExposureAccess(analysis, gov),
		HasWildcardPolicy: analysis.Policy.HasWildcardActions,
	})

	storageModel := s3storage.BuildModel(s3storage.BuildModelInput{
		Bucket:                 bucket,
		AccountPAB:             accountPAB,
		EffectivePAB:           effectivePAB,
		Access:                 access,
		TransportEnforcesHTTPS: analysis.Transport.EnforcesHTTPS,
	})
	awsS3Evidence := s3storage.BuildAWSS3Evidence(bucket, analysis)

	props := map[string]any{
		"storage": ToMap(storageModel),
	}
	if sourceEvidence := s3storage.BuildSourceEvidence(analysis); sourceEvidence != nil {
		props["source_evidence"] = ToMap(sourceEvidence)
	}
	if evidenceMap := ToMap(awsS3Evidence); len(evidenceMap) > 0 {
		props["vendor"] = map[string]any{
			"aws": map[string]any{
				"s3": evidenceMap,
			},
		}
	}

	return asset.Asset{
		ID:         asset.ID(bucket.Name.Name()),
		Type:       s3storage.TypeS3Bucket,
		Vendor:     s3storage.VendorAWS,
		Properties: props,
	}
}

func computeEffectivePAB(account, bucket *s3storage.PublicAccessBlock) s3storage.PublicAccessBlock {
	var eff s3storage.PublicAccessBlock
	mergePublicAccessBlock(&eff, account)
	mergePublicAccessBlock(&eff, bucket)
	return eff
}

func mergePublicAccessBlock(effective *s3storage.PublicAccessBlock, candidate *s3storage.PublicAccessBlock) {
	if candidate == nil {
		return
	}
	effective.BlockPublicAcls = effective.BlockPublicAcls || candidate.BlockPublicAcls
	effective.IgnorePublicAcls = effective.IgnorePublicAcls || candidate.IgnorePublicAcls
	effective.BlockPublicPolicy = effective.BlockPublicPolicy || candidate.BlockPublicPolicy
	effective.RestrictPublicBuckets = effective.RestrictPublicBuckets || candidate.RestrictPublicBuckets
}

// ToIdentityVisibility maps an S3 policy analysis to the exposure domain Visibility.
func ToIdentityVisibility(policy s3policy.Analysis) s3exposure.Visibility {
	return s3exposure.Visibility{
		Public: s3exposure.Capabilities{
			Read:  policy.AllowsPublicRead,
			Write: policy.AllowsPublicWrite,
			List:  policy.AllowsPublicList,
			Admin: policy.AllowsPublicACLRead || policy.AllowsPublicACLWrite,
		},
		Authenticated: s3exposure.Capabilities{
			Read:  policy.AllowsAuthenticatedRead,
			Write: policy.AllowsAuthenticatedWrite,
			List:  policy.AllowsAuthenticatedList,
			Admin: policy.AllowsAuthenticatedACLRead || policy.AllowsAuthenticatedACLWrite,
		},
	}
}

// ToResourceVisibility maps an S3 ACL analysis to the exposure domain Visibility.
func ToResourceVisibility(acl s3acl.Analysis) s3exposure.Visibility {
	pub := s3exposure.Capabilities{
		Read:  acl.AllowsPublicRead,
		Write: acl.AllowsPublicWrite,
		Admin: acl.AllowsPublicACLRead || acl.AllowsPublicACLWrite,
	}
	auth := s3exposure.Capabilities{
		Read:  acl.AllowsAuthenticatedRead,
		Write: acl.AllowsAuthenticatedWrite,
		Admin: acl.AllowsAuthenticatedACLRead || acl.AllowsAuthenticatedACLWrite,
	}
	if acl.HasFullControlPublic {
		pub = s3exposure.Capabilities{Read: true, Write: true, List: true, Delete: true, Admin: true}
	}
	if acl.HasFullControlAuthenticated {
		auth = s3exposure.Capabilities{Read: true, Write: true, List: true, Delete: true, Admin: true}
	}
	return s3exposure.Visibility{
		Public:        pub,
		Authenticated: auth,
	}
}

// ToGovernanceOverrides maps an S3 public access block to the exposure domain GovernanceOverrides.
func ToGovernanceOverrides(pab s3storage.PublicAccessBlock) s3exposure.GovernanceOverrides {
	return s3exposure.GovernanceOverrides{
		BlockIdentityBoundPublicAccess: pab.BlockPublicPolicy || pab.RestrictPublicBuckets,
		BlockResourceBoundPublicAccess: pab.BlockPublicAcls || pab.IgnorePublicAcls,
		EnforceStrictPublicInheritance: pab.BlockPublicAcls && pab.IgnorePublicAcls &&
			pab.BlockPublicPolicy && pab.RestrictPublicBuckets,
	}
}

func toCrossAccountAccess(ca s3policy.CrossAccountAnalysis) s3exposure.CrossAccountAccess {
	return s3exposure.CrossAccountAccess{
		ExternalAccountARNs: ca.ExternalAccountARNs,
		ExternalAccountIDs:  ca.ExternalAccountIDs,
		HasExternalAccess:   ca.HasExternalAccess,
		HasExternalWrite:    ca.HasExternalWrite,
	}
}

func toNetworkScopeAccess(policy s3policy.Analysis) s3exposure.NetworkScopeAccess {
	return s3exposure.NetworkScopeAccess{
		HasIPCondition:        policy.HasIPCondition,
		HasVPCCondition:       policy.HasVPCCondition,
		EffectiveNetworkScope: policy.EffectiveNetworkScope,
	}
}

func toACLFullControlAccess(acl s3acl.Analysis) s3exposure.ACLFullControlAccess {
	return s3exposure.ACLFullControlAccess{
		FullControlPublic:        acl.HasFullControlPublic,
		FullControlAuthenticated: acl.HasFullControlAuthenticated,
	}
}

func toPrefixExposureAccess(analysis s3storage.S3AnalysisResult, gov s3exposure.GovernanceOverrides) s3exposure.PrefixExposureAccess {
	aclPublicReadAll := analysis.HasACL && analysis.ACL.AllowsPublicRead
	return s3exposure.PrefixExposureAccess{
		HasIdentityEvidence:   analysis.HasPolicy,
		HasResourceEvidence:   analysis.HasACL,
		IdentityReadScopes:    analysis.PrefixScopes.Scopes,
		IdentitySourceByScope: analysis.PrefixScopes.SourceByScope,
		IdentityReadBlocked:   gov.BlockIdentityBoundPublicAccess,
		ResourceReadAll:       aclPublicReadAll,
		ResourceReadBlocked:   gov.BlockResourceBoundPublicAccess,
	}
}
