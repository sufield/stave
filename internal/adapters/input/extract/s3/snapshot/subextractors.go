package snapshot

import (
	"encoding/json"

	s3acl "github.com/sufield/stave/internal/adapters/input/extract/s3/acl"
	s3storage "github.com/sufield/stave/internal/adapters/input/extract/s3/storage"
)

type bucketSubExtractor func(obs *S3Observation, data []byte) error

type subExtractorSpec struct {
	api   string
	label string
	apply bucketSubExtractor
}

var s3Manifest = []subExtractorSpec{
	{
		api:   "get-bucket-tagging",
		label: "tags",
		apply: func(obs *S3Observation, data []byte) error {
			var resp TaggingResponse
			if err := json.Unmarshal(data, &resp); err != nil {
				return err
			}
			for _, tag := range resp.TagSet {
				obs.Tags[tag.Key] = tag.Value
			}
			return nil
		},
	},
	{
		api:   "get-bucket-policy",
		label: "policy",
		apply: func(obs *S3Observation, data []byte) error {
			var resp PolicyResponse
			if err := json.Unmarshal(data, &resp); err != nil {
				return err
			}
			obs.PolicyJSON = resp.Policy
			return nil
		},
	},
	{
		api:   "get-bucket-acl",
		label: "acl",
		apply: func(obs *S3Observation, data []byte) error {
			var resp ACLResponse
			if err := json.Unmarshal(data, &resp); err != nil {
				return err
			}
			grants := make([]s3acl.Grant, 0, len(resp.Grants))
			for _, grant := range resp.Grants {
				grants = append(grants, s3acl.Grant{
					Grantee:    firstNonEmpty(grant.Grantee.URI, grant.Grantee.ID),
					Permission: grant.Permission,
				})
			}
			obs.ACL = s3acl.New(grants)
			return nil
		},
	},
	{
		api:   "get-public-access-block",
		label: "public-access-block",
		apply: func(obs *S3Observation, data []byte) error {
			var resp PublicAccessBlockResponse
			if err := json.Unmarshal(data, &resp); err != nil {
				return err
			}
			cfg := resp.PublicAccessBlockConfiguration
			obs.PublicAccessBlock = &s3storage.PublicAccessBlock{
				BlockPublicAcls:       cfg.BlockPublicAcls,
				IgnorePublicAcls:      cfg.IgnorePublicAcls,
				BlockPublicPolicy:     cfg.BlockPublicPolicy,
				RestrictPublicBuckets: cfg.RestrictPublicBuckets,
			}
			return nil
		},
	},
}
