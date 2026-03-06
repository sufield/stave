package snapshot

import (
	s3acl "github.com/sufield/stave/internal/adapters/input/extract/s3/acl"
	s3storage "github.com/sufield/stave/internal/adapters/input/extract/s3/storage"
)

// ListBucketsResponse represents the AWS CLI list-buckets output.
type ListBucketsResponse struct {
	Buckets []struct {
		Name         string `json:"Name"`
		CreationDate string `json:"CreationDate"`
	} `json:"Buckets"`
	Owner struct {
		DisplayName string `json:"DisplayName"`
		ID          string `json:"ID"`
	} `json:"Owner"`
}

// TaggingResponse represents the AWS CLI get-bucket-tagging output.
type TaggingResponse struct {
	TagSet []struct {
		Key   string `json:"Key"`
		Value string `json:"Value"`
	} `json:"TagSet"`
}

// PolicyResponse represents the AWS CLI get-bucket-policy output.
type PolicyResponse struct {
	Policy string `json:"Policy"`
}

// ACLResponse represents the AWS CLI get-bucket-acl output.
type ACLResponse struct {
	Owner struct {
		DisplayName string `json:"DisplayName"`
		ID          string `json:"ID"`
	} `json:"Owner"`
	Grants []struct {
		Grantee struct {
			Type         string `json:"Type"`
			URI          string `json:"URI"`
			ID           string `json:"ID"`
			DisplayName  string `json:"DisplayName"`
			EmailAddress string `json:"EmailAddress"`
		} `json:"Grantee"`
		Permission string `json:"Permission"`
	} `json:"Grants"`
}

// PublicAccessBlockResponse represents the AWS CLI get-public-access-block output.
type PublicAccessBlockResponse struct {
	PublicAccessBlockConfiguration struct {
		BlockPublicAcls       bool `json:"BlockPublicAcls"`
		IgnorePublicAcls      bool `json:"IgnorePublicAcls"`
		BlockPublicPolicy     bool `json:"BlockPublicPolicy"`
		RestrictPublicBuckets bool `json:"RestrictPublicBuckets"`
	} `json:"PublicAccessBlockConfiguration"`
}

// S3Observation represents the normalized observation for a single S3 bucket.
// This is the extraction-to-evaluation contract for observation schema obs.v0.1.
type S3Observation struct {
	BucketName        string                       `json:"bucket_name"`
	BucketARN         string                       `json:"bucket_arn,omitempty"`
	Tags              map[string]string            `json:"tags,omitempty"`
	PolicyJSON        string                       `json:"policy_json,omitempty"`
	ACL               *s3acl.Entry                 `json:"-"`
	PublicAccessBlock *s3storage.PublicAccessBlock `json:"public_access_block,omitempty"`
	Evidence          []string                     `json:"evidence"`
	MissingInputs     []string                     `json:"missing_inputs,omitempty"`
}
