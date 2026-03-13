package storage

import (
	s3acl "github.com/sufield/stave/internal/adapters/input/extract/s3/acl"
	s3policy "github.com/sufield/stave/internal/adapters/input/extract/s3/policy"
)

type prefixExposureModelInput struct {
	PrefixScopes   s3policy.PrefixScopeAnalysis
	HasPolicy      bool
	ACLAnalysis    s3acl.Analysis
	HasACLAnalysis bool
	PolicyBlocked  bool
	ACLBlocked     bool
}

func buildPrefixExposureModel(in prefixExposureModelInput) S3PrefixExposure {
	aclPublicReadAll := in.HasACLAnalysis && in.ACLAnalysis.AllowsPublicRead

	out := S3PrefixExposure{
		HasIdentityEvidence:   in.HasPolicy,
		HasResourceEvidence:   in.HasACLAnalysis,
		IdentityReadScopes:    in.PrefixScopes.Scopes,
		IdentitySourceByScope: in.PrefixScopes.SourceByScope,
		IdentityReadBlocked:   in.PolicyBlocked,
		ResourceReadAll:       aclPublicReadAll,
		ResourceReadBlocked:   in.ACLBlocked,
	}
	return out
}
