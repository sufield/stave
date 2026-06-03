package acl

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/platform/fsutil"
	s3acl "github.com/sufield/stave/internal/platform/providers/aws/s3/acl"
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
		return fmt.Errorf("read input: %w", err)
	}

	var grants []s3acl.Grant
	if err := json.Unmarshal(data, &grants); err != nil {
		return fmt.Errorf("parse ACL grants: %w", err)
	}

	list := s3acl.New(grants)
	assessment := list.Assess()

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
	}

	enc := json.NewEncoder(in.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(Report{Assessment: assessment, GrantDetails: details})
}
