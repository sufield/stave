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
		toExposurePolicyAnalysis(analysis.Policy),
		analysis.HasACL,
		toExposureACLAnalysis(analysis.ACL),
		toExposurePublicAccessBlock(effectivePAB),
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

func toExposurePolicyAnalysis(policy s3policy.Analysis) s3exposure.PolicyAnalysis {
	return s3exposure.PolicyAnalysis{
		AllowsPublicRead:            policy.AllowsPublicRead,
		AllowsPublicList:            policy.AllowsPublicList,
		AllowsPublicWrite:           policy.AllowsPublicWrite,
		AllowsPublicACLRead:         policy.AllowsPublicACLRead,
		AllowsPublicACLWrite:        policy.AllowsPublicACLWrite,
		AllowsAuthenticatedRead:     policy.AllowsAuthenticatedRead,
		AllowsAuthenticatedList:     policy.AllowsAuthenticatedList,
		AllowsAuthenticatedWrite:    policy.AllowsAuthenticatedWrite,
		AllowsAuthenticatedACLRead:  policy.AllowsAuthenticatedACLRead,
		AllowsAuthenticatedACLWrite: policy.AllowsAuthenticatedACLWrite,
	}
}

func toExposureACLAnalysis(acl s3acl.Analysis) s3exposure.ACLAnalysis {
	return s3exposure.ACLAnalysis{
		AllowsPublicRead:            acl.AllowsPublicRead,
		AllowsPublicWrite:           acl.AllowsPublicWrite,
		AllowsPublicACLRead:         acl.AllowsPublicACLRead,
		AllowsPublicACLWrite:        acl.AllowsPublicACLWrite,
		AllowsAuthenticatedRead:     acl.AllowsAuthenticatedRead,
		AllowsAuthenticatedWrite:    acl.AllowsAuthenticatedWrite,
		AllowsAuthenticatedACLRead:  acl.AllowsAuthenticatedACLRead,
		AllowsAuthenticatedACLWrite: acl.AllowsAuthenticatedACLWrite,
		HasFullControlPublic:        acl.HasFullControlPublic,
		HasFullControlAuthenticated: acl.HasFullControlAuthenticated,
	}
}

func toExposurePublicAccessBlock(pab s3storage.PublicAccessBlock) s3exposure.PublicAccessBlock {
	return s3exposure.PublicAccessBlock{
		BlockPublicAcls:       pab.BlockPublicAcls,
		IgnorePublicAcls:      pab.IgnorePublicAcls,
		BlockPublicPolicy:     pab.BlockPublicPolicy,
		RestrictPublicBuckets: pab.RestrictPublicBuckets,
	}
}
