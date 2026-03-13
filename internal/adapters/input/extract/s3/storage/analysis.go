package storage

import (
	s3acl "github.com/sufield/stave/internal/adapters/input/extract/s3/acl"
	s3policy "github.com/sufield/stave/internal/adapters/input/extract/s3/policy"
)

type S3AnalysisResult struct {
	HasPolicy    bool
	Policy       s3policy.Analysis
	HasACL       bool
	ACL          s3acl.Analysis
	Transport    s3policy.TransportEncryptionAnalysis
	CrossAccount s3policy.CrossAccountAnalysis
	PrefixScopes s3policy.PrefixScopeAnalysis
}

func (b *S3Bucket) Analyze() S3AnalysisResult {
	result := S3AnalysisResult{}
	if b == nil {
		return result
	}
	if b.PolicyJSON != "" {
		result.HasPolicy = true
		engine, err := s3policy.NewEngine(b.PolicyJSON)
		if err == nil {
			result.Policy = engine.FullAnalysis()
			result.Transport = engine.TransportEncryptionAnalysis()
			result.CrossAccount = engine.CrossAccountAnalysis()
			result.PrefixScopes = engine.PrefixScopeAnalysis()
		}
	}
	if len(b.ACLGrants) > 0 {
		result.HasACL = true
		result.ACL = s3acl.Analyze(b.ACLGrants)
	}
	return result
}
