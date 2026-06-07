package stave

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/sufield/stave/internal/core/evaluation/risk"
	s3acl "github.com/sufield/stave/internal/platform/providers/aws/s3/acl"
)

type aclReport struct {
	Assessment   s3acl.Assessment `json:"assessment"`
	GrantDetails []aclGrantDetail `json:"grant_details"`
}

type aclGrantDetail struct {
	Grantee      string          `json:"grantee"`
	Permission   string          `json:"permission"`
	Audience     string          `json:"audience"`
	IsPublic     bool            `json:"is_public"`
	HasFullCtrl  bool            `json:"has_full_control"`
	PermissionID risk.Permission `json:"permission_mask"`
}

// InspectACL parses a JSON array of S3 ACL grants, assesses their
// security posture (public/authenticated/full-control), and returns the
// analysis as indented JSON with a trailing newline (matching
// json.Encoder). It is the library entry point behind
// `stave inspect acl`.
func InspectACL(data []byte) ([]byte, error) {
	var grants []s3acl.Grant
	if err := json.Unmarshal(data, &grants); err != nil {
		return nil, fmt.Errorf("parse ACL grants: %w", err)
	}

	list := s3acl.New(grants)
	assessment := list.Assess()

	// Nil (not empty) slice so a zero-grant input serialises as
	// "grant_details": null, matching the pre-facade output.
	var details []aclGrantDetail
	for _, g := range grants {
		details = append(details, aclGrantDetail{
			Grantee:      g.Grantee,
			Permission:   string(g.Permission),
			Audience:     g.Audience().String(),
			IsPublic:     g.IsPublic(),
			HasFullCtrl:  g.HasFullControl(),
			PermissionID: g.Permissions(),
		})
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(aclReport{Assessment: assessment, GrantDetails: details}); err != nil {
		return nil, fmt.Errorf("encode ACL report: %w", err)
	}
	return buf.Bytes(), nil
}
