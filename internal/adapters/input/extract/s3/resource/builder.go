package resource

import (
	s3acl "github.com/sufield/stave/internal/adapters/input/extract/s3/acl"
	s3policy "github.com/sufield/stave/internal/adapters/input/extract/s3/policy"
	s3storage "github.com/sufield/stave/internal/adapters/input/extract/s3/storage"
	"github.com/sufield/stave/internal/domain/asset"
	s3exposure "github.com/sufield/stave/internal/domain/evaluation/exposure"
	"github.com/sufield/stave/internal/domain/kernel"
)

// BuildBucketAsset converts a bucket model into a normalized asset.Asset.
func BuildBucketAsset(bucket *s3storage.S3Bucket, accountPAB *s3storage.PublicAccessBlock) asset.Asset {
	analysis := bucket.Analyze()
	effectivePAB := computeEffectivePAB(accountPAB, bucket.PublicAccessBlock)

	visibility := s3exposure.BuildVisibilityResult(
		analysis.HasPolicy,
		ToExposurePolicyAnalysis(analysis.Policy),
		analysis.HasACL,
		ToExposureACLAnalysis(analysis.ACL),
		ToExposurePublicAccessBlock(effectivePAB),
	)

	storageModel := s3storage.BuildModel(s3storage.BuildModelInput{
		Bucket:       bucket,
		AccountPAB:   accountPAB,
		EffectivePAB: effectivePAB,
		Analysis:     analysis,
		Visibility:   visibility,
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
		ID:         asset.ID(bucket.Name),
		Type:       kernel.TypeS3Bucket,
		Vendor:     kernel.VendorAWS,
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

// ToExposurePolicyAnalysis maps an S3 policy analysis to the exposure domain type.
func ToExposurePolicyAnalysis(policy s3policy.Analysis) s3exposure.PolicyAnalysis {
	return s3exposure.PolicyAnalysis{
		AccessFlags: s3exposure.AccessFlags{
			PublicRead:            policy.AllowsPublicRead,
			PublicWrite:           policy.AllowsPublicWrite,
			PublicACLRead:         policy.AllowsPublicACLRead,
			PublicACLWrite:        policy.AllowsPublicACLWrite,
			AuthenticatedRead:     policy.AllowsAuthenticatedRead,
			AuthenticatedWrite:    policy.AllowsAuthenticatedWrite,
			AuthenticatedACLRead:  policy.AllowsAuthenticatedACLRead,
			AuthenticatedACLWrite: policy.AllowsAuthenticatedACLWrite,
		},
		PublicList:        policy.AllowsPublicList,
		AuthenticatedList: policy.AllowsAuthenticatedList,
	}
}

// ToExposureACLAnalysis maps an S3 ACL analysis to the exposure domain type.
func ToExposureACLAnalysis(acl s3acl.Analysis) s3exposure.ACLAnalysis {
	return s3exposure.ACLAnalysis{
		AccessFlags: s3exposure.AccessFlags{
			PublicRead:            acl.AllowsPublicRead,
			PublicWrite:           acl.AllowsPublicWrite,
			PublicACLRead:         acl.AllowsPublicACLRead,
			PublicACLWrite:        acl.AllowsPublicACLWrite,
			AuthenticatedRead:     acl.AllowsAuthenticatedRead,
			AuthenticatedWrite:    acl.AllowsAuthenticatedWrite,
			AuthenticatedACLRead:  acl.AllowsAuthenticatedACLRead,
			AuthenticatedACLWrite: acl.AllowsAuthenticatedACLWrite,
		},
		PublicFullControl:        acl.HasFullControlPublic,
		AuthenticatedFullControl: acl.HasFullControlAuthenticated,
	}
}

// ToExposurePublicAccessBlock maps an S3 public access block to the exposure domain type.
func ToExposurePublicAccessBlock(pab s3storage.PublicAccessBlock) s3exposure.PublicAccessBlock {
	return s3exposure.PublicAccessBlock{
		BlockPublicACLs:       pab.BlockPublicAcls,
		IgnorePublicACLs:      pab.IgnorePublicAcls,
		BlockPublicPolicy:     pab.BlockPublicPolicy,
		RestrictPublicBuckets: pab.RestrictPublicBuckets,
	}
}
