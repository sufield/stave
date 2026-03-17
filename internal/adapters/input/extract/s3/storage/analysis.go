package storage

import (
	s3acl "github.com/sufield/stave/internal/domain/s3/acl"
	s3policy "github.com/sufield/stave/internal/domain/s3/policy"
)

type S3AnalysisResult struct {
	HasPolicy    bool
	Policy       s3policy.Assessment
	HasACL       bool
	ACL          s3acl.Assessment
	PrefixScopes s3policy.PrefixScopeAnalysis
}

func (b *S3Bucket) Analyze() S3AnalysisResult {
	result := S3AnalysisResult{}
	if b == nil {
		return result
	}
	if b.PolicyJSON != "" {
		result.HasPolicy = true
		doc, err := s3policy.Parse(b.PolicyJSON)
		if err == nil {
			result.Policy = doc.Assess()
			result.PrefixScopes = doc.PrefixScopeAnalysis()
		}
	}
	if len(b.ACLGrants) > 0 {
		result.HasACL = true
		result.ACL = s3acl.Assess(b.ACLGrants)
	}
	return result
}
