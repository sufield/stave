package acl

import (
	"encoding/json"
	"fmt"
	"io"

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

// Input is the per-run payload assembled at the RunE boundary. No
// cobra reference — RunE resolves Stdin/Stdout before calling run,
// so this package can stay off the cobra import graph.
type Input struct {
	Stdin  io.Reader
	Stdout io.Writer
	File   string
}

func run(in Input) error {
	data, err := fsutil.ReadFileOrStdin(in.File, in.Stdin)
	if err != nil {
		return err
	}

	var grants []s3acl.Grant
	if err := json.Unmarshal(data, &grants); err != nil {
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
		_ = s3acl.IsPublicGrantee(g.Grantee)
	}

	enc := json.NewEncoder(in.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(Report{Assessment: assessment, GrantDetails: details})
}
