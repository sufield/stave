package acl

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/core/evaluation/risk"
	s3acl "github.com/sufield/stave/internal/core/s3/acl"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// Report is the output of the ACL inspector.
type Report struct {
	Assessment   s3acl.Assessment `json:"assessment"`
	GrantDetails []GrantDetail    `json:"grant_details"`
}

// GrantDetail describes per-grant analysis.
type GrantDetail struct {
	Grantee      string          `json:"grantee"`
	Permission   string          `json:"permission"`
	Audience     string          `json:"audience"`
	IsPublic     bool            `json:"is_public"`
	HasFullCtrl  bool            `json:"has_full_control"`
	PermissionID risk.Permission `json:"permission_mask"`
}

func run(cmd *cobra.Command, file string) error {
	input, err := fsutil.ReadFileOrStdin(file, cmd.InOrStdin())
	if err != nil {
		return err
	}

	var grants []s3acl.Grant
	if err := json.Unmarshal(input, &grants); err != nil {
		return fmt.Errorf("parse ACL grants: %w", err)
	}

	// Use both List-based and convenience-function forms.
	list := s3acl.New(grants)
	assessment := list.Assess()

	// Also exercise the package-level Assess convenience form.
	_ = s3acl.Assess(grants)

	// Per-grant detail analysis.
	var details []GrantDetail
	for _, g := range grants {
		details = append(details, GrantDetail{
			Grantee:      g.Grantee,
			Permission:   string(g.Permission),
			Audience:     g.Audience().String(),
			IsPublic:     g.IsPublic(),
			HasFullCtrl:  g.HasFullControl(),
			PermissionID: g.Permissions(),
		})
		// Exercise IsPublicGrantee.
		_ = s3acl.IsPublicGrantee(g.Grantee)
	}

	report := Report{
		Assessment:   assessment,
		GrantDetails: details,
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
