package snapshot

import (
	s3acl "github.com/sufield/stave/internal/adapters/input/extract/s3/acl"
	s3policy "github.com/sufield/stave/internal/adapters/input/extract/s3/policy"
	s3resource "github.com/sufield/stave/internal/adapters/input/extract/s3/resource"
	s3storage "github.com/sufield/stave/internal/adapters/input/extract/s3/storage"
	"github.com/sufield/stave/internal/domain/asset"
	s3exposure "github.com/sufield/stave/internal/domain/evaluation/exposure"
	"github.com/sufield/stave/internal/domain/kernel"
)

type snapshotResourceProperties struct {
	BucketName               string            `json:"bucket_name"`
	ARN                      string            `json:"arn,omitempty"`
	Evidence                 []string          `json:"evidence"`
	MissingInputs            []string          `json:"missing_inputs,omitempty"`
	PolicyJSON               string            `json:"policy_json,omitempty"`
	PolicyAllowsPublicRead   *bool             `json:"policy_allows_public_read,omitempty"`
	PolicyAllowsPublicList   *bool             `json:"policy_allows_public_list,omitempty"`
	PolicyPublicStatements   []kernel.StatementID `json:"policy_public_statements,omitempty"`
	PolicyStatus             string            `json:"policy_status,omitempty"`
	ACLGrants                []s3acl.Grant     `json:"acl_grants,omitempty"`
	ACLAllowsPublicRead      *bool             `json:"acl_allows_public_read,omitempty"`
	ACLPublicGrantees        []kernel.GranteeID `json:"acl_public_grantees,omitempty"`
	ACLStatus                string            `json:"acl_status,omitempty"`
	PublicAccessBlock        *snapshotPABBlock `json:"public_access_block,omitempty"`
	PublicAccessFullyBlocked *bool             `json:"public_access_fully_blocked,omitempty"`
	PublicAccessBlockStatus  string            `json:"public_access_block_status,omitempty"`
	Public                   bool              `json:"public"`
	SafetyProvable           bool              `json:"safety_provable"`
	Tags                     map[string]string `json:"tags,omitempty"`
	SourceEvidence           map[string]any    `json:"source_evidence,omitempty"`
}

type snapshotPABBlock struct {
	BlockPublicAcls       bool `json:"block_public_acls"`
	IgnorePublicAcls      bool `json:"ignore_public_acls"`
	BlockPublicPolicy     bool `json:"block_public_policy"`
	RestrictPublicBuckets bool `json:"restrict_public_buckets"`
}

func (e *SnapshotExtractor) observationToAsset(obs S3Observation) asset.Asset {
	props := snapshotResourceProperties{
		BucketName:    obs.BucketName,
		ARN:           obs.BucketARN,
		Evidence:      obs.Evidence,
		MissingInputs: obs.MissingInputs,
		Tags:          obs.Tags,
	}

	policyAnalysis, hasPolicy, policyMissing := applyPolicyObservation(obs, &props)
	aclAnalysis, aclMissing := applyACLObservation(obs, &props)
	effectivePAB := applyPABObservation(obs, &props)
	effective := s3exposure.ResolveEffectiveVisibility(
		s3resource.ToIdentityVisibility(policyAnalysis),
		s3resource.ToResourceVisibility(aclAnalysis),
		s3resource.ToGovernanceOverrides(effectivePAB),
	)
	props.Public = effective.IsExposed() || (hasPolicy && policyAnalysis.HasWildcardActions)
	props.SafetyProvable = !policyMissing && !aclMissing
	props.SourceEvidence = buildSnapshotSourceEvidence(props)

	return asset.Asset{
		ID:         asset.ID(obs.BucketName),
		Type:       s3storage.TypeS3Bucket,
		Vendor:     s3storage.VendorAWS,
		Properties: snapshotPropertiesToMap(props),
	}
}

func applyPolicyObservation(obs S3Observation, props *snapshotResourceProperties) (s3policy.Analysis, bool, bool) {
	policyMissing := s3resource.ContainsSubstring(obs.MissingInputs, "get-bucket-policy")
	if obs.PolicyJSON == "" {
		if policyMissing {
			props.PolicyStatus = "unknown"
		}
		return s3policy.Analysis{}, false, policyMissing
	}
	props.PolicyJSON = obs.PolicyJSON
	policyAnalysis := s3policy.AnalyzePolicy(obs.PolicyJSON)
	allowsRead := policyAnalysis.AllowsPublicRead
	props.PolicyAllowsPublicRead = &allowsRead
	allowsList := policyAnalysis.AllowsPublicList
	props.PolicyAllowsPublicList = &allowsList
	props.PolicyPublicStatements = policyAnalysis.PublicStatements
	return policyAnalysis, true, policyMissing
}

func applyACLObservation(obs S3Observation, props *snapshotResourceProperties) (s3acl.Analysis, bool) {
	aclMissing := s3resource.ContainsSubstring(obs.MissingInputs, "get-bucket-acl")
	if obs.ACL == nil {
		if aclMissing {
			props.ACLStatus = "unknown"
		}
		return s3acl.Analysis{}, aclMissing
	}
	grants := obs.ACL.Grants()
	if len(grants) > 0 {
		props.ACLGrants = grants
	}
	aclAnalysis := obs.ACL.Analyze()
	aclAllowsRead := aclAnalysis.AllowsPublicRead
	props.ACLAllowsPublicRead = &aclAllowsRead
	props.ACLPublicGrantees = aclAnalysis.PublicGrantees
	return aclAnalysis, aclMissing
}

func applyPABObservation(obs S3Observation, props *snapshotResourceProperties) s3storage.PublicAccessBlock {
	pabMissing := s3resource.ContainsSubstring(obs.MissingInputs, "get-public-access-block")
	if obs.PublicAccessBlock == nil {
		if pabMissing {
			props.PublicAccessBlockStatus = "unknown"
		}
		return s3storage.PublicAccessBlock{}
	}
	props.PublicAccessBlock = &snapshotPABBlock{
		BlockPublicAcls:       obs.PublicAccessBlock.BlockPublicAcls,
		IgnorePublicAcls:      obs.PublicAccessBlock.IgnorePublicAcls,
		BlockPublicPolicy:     obs.PublicAccessBlock.BlockPublicPolicy,
		RestrictPublicBuckets: obs.PublicAccessBlock.RestrictPublicBuckets,
	}
	effectivePAB := s3storage.PublicAccessBlock{
		BlockPublicAcls:       obs.PublicAccessBlock.BlockPublicAcls,
		IgnorePublicAcls:      obs.PublicAccessBlock.IgnorePublicAcls,
		BlockPublicPolicy:     obs.PublicAccessBlock.BlockPublicPolicy,
		RestrictPublicBuckets: obs.PublicAccessBlock.RestrictPublicBuckets,
	}
	allBlocked := s3resource.ToGovernanceOverrides(effectivePAB).IsHardened()
	props.PublicAccessFullyBlocked = &allBlocked
	return effectivePAB
}

func buildSnapshotSourceEvidence(props snapshotResourceProperties) map[string]any {
	sourceEvidence := make(map[string]any, 2)
	if len(props.PolicyPublicStatements) > 0 {
		sourceEvidence["policy_public_statements"] = props.PolicyPublicStatements
	}
	if len(props.ACLPublicGrantees) > 0 {
		sourceEvidence["acl_public_grantees"] = props.ACLPublicGrantees
	}
	if len(sourceEvidence) == 0 {
		return nil
	}
	return sourceEvidence
}

func snapshotPropertiesToMap(props snapshotResourceProperties) map[string]any {
	out := map[string]any{
		"bucket_name":     props.BucketName,
		"evidence":        props.Evidence,
		"public":          props.Public,
		"safety_provable": props.SafetyProvable,
	}

	addSnapshotIdentityFields(out, props)
	addSnapshotPolicyFields(out, props)
	addSnapshotACLFields(out, props)
	addSnapshotPABFields(out, props)
	addSnapshotMetadataFields(out, props)
	return out
}

func addSnapshotIdentityFields(out map[string]any, props snapshotResourceProperties) {
	if props.ARN != "" {
		out["arn"] = props.ARN
	}
	if len(props.MissingInputs) > 0 {
		out["missing_inputs"] = props.MissingInputs
	}
}

func addSnapshotPolicyFields(out map[string]any, props snapshotResourceProperties) {
	if props.PolicyJSON != "" {
		out["policy_json"] = props.PolicyJSON
	}
	if props.PolicyAllowsPublicRead != nil {
		out["policy_allows_public_read"] = *props.PolicyAllowsPublicRead
	}
	if props.PolicyAllowsPublicList != nil {
		out["policy_allows_public_list"] = *props.PolicyAllowsPublicList
	}
	if len(props.PolicyPublicStatements) > 0 {
		out["policy_public_statements"] = props.PolicyPublicStatements
	}
	if props.PolicyStatus != "" {
		out["policy_status"] = props.PolicyStatus
	}
}

func addSnapshotACLFields(out map[string]any, props snapshotResourceProperties) {
	if len(props.ACLGrants) > 0 {
		out["acl_grants"] = props.ACLGrants
	}
	if props.ACLAllowsPublicRead != nil {
		out["acl_allows_public_read"] = *props.ACLAllowsPublicRead
	}
	if len(props.ACLPublicGrantees) > 0 {
		out["acl_public_grantees"] = props.ACLPublicGrantees
	}
	if props.ACLStatus != "" {
		out["acl_status"] = props.ACLStatus
	}
}

func addSnapshotPABFields(out map[string]any, props snapshotResourceProperties) {
	if props.PublicAccessBlock != nil {
		out["public_access_block"] = s3resource.ToMap(props.PublicAccessBlock)
	}
	if props.PublicAccessFullyBlocked != nil {
		out["public_access_fully_blocked"] = *props.PublicAccessFullyBlocked
	}
	if props.PublicAccessBlockStatus != "" {
		out["public_access_block_status"] = props.PublicAccessBlockStatus
	}
}

func addSnapshotMetadataFields(out map[string]any, props snapshotResourceProperties) {
	if len(props.Tags) > 0 {
		out["tags"] = props.Tags
	}
	if len(props.SourceEvidence) > 0 {
		out["source_evidence"] = props.SourceEvidence
	}
}
