package iam

import (
	"testing"

	"github.com/sufield/stave/internal/core/access"
	"github.com/sufield/stave/internal/core/asset"
)

func TestApplyResourcePolicyGrants_CrossAccountAND(t *testing.T) {
	tests := []struct {
		name           string
		identityAllow  []ActionGrant
		resourceGrants []resourceGrant
		wantActions    int
	}{
		{
			name:          "same-account: resource grant included without identity match",
			identityAllow: nil,
			resourceGrants: []resourceGrant{{
				resourceARN:    "arn:aws:s3:::bucket",
				actions:        []string{"s3:GetObject"},
				isCrossAccount: false,
			}},
			wantActions: 1,
		},
		{
			name: "cross-account: both allow → included",
			identityAllow: []ActionGrant{
				{Action: "s3:GetObject", Resource: "*", Source: "identity"},
			},
			resourceGrants: []resourceGrant{{
				resourceARN:    "arn:aws:s3:::bucket",
				actions:        []string{"s3:GetObject"},
				isCrossAccount: true,
			}},
			wantActions: 1,
		},
		{
			name: "cross-account: identity allows, no resource → no resource grant",
			identityAllow: []ActionGrant{
				{Action: "s3:GetObject", Resource: "*", Source: "identity"},
			},
			resourceGrants: nil,
			wantActions:    0,
		},
		{
			name:          "cross-account: no identity, resource allows → filtered out",
			identityAllow: nil,
			resourceGrants: []resourceGrant{{
				resourceARN:    "arn:aws:s3:::bucket",
				actions:        []string{"s3:GetObject"},
				isCrossAccount: true,
			}},
			wantActions: 0,
		},
		{
			name: "cross-account: identity wildcard covers resource action",
			identityAllow: []ActionGrant{
				{Action: "s3:*", Resource: "*", Source: "identity"},
			},
			resourceGrants: []resourceGrant{{
				resourceARN:    "arn:aws:s3:::bucket",
				actions:        []string{"s3:GetObject", "s3:PutObject"},
				isCrossAccount: true,
			}},
			wantActions: 2,
		},
		{
			name: "cross-account: identity full wildcard covers all",
			identityAllow: []ActionGrant{
				{Action: "*", Resource: "*", Source: "identity"},
			},
			resourceGrants: []resourceGrant{{
				resourceARN:    "arn:aws:s3:::bucket",
				actions:        []string{"s3:GetObject"},
				isCrossAccount: true,
			}},
			wantActions: 1,
		},
		{
			name: "cross-account: partial match filters non-matching actions",
			identityAllow: []ActionGrant{
				{Action: "s3:GetObject", Resource: "*", Source: "identity"},
			},
			resourceGrants: []resourceGrant{{
				resourceARN:    "arn:aws:s3:::bucket",
				actions:        []string{"s3:GetObject", "s3:DeleteObject"},
				isCrossAccount: true,
			}},
			wantActions: 1,
		},
		{
			name:          "public grant: always included regardless of identity",
			identityAllow: nil,
			resourceGrants: []resourceGrant{{
				resourceARN: "arn:aws:s3:::public-bucket",
				actions:     []string{"s3:GetObject"},
				isPublic:    true,
			}},
			wantActions: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			principal := "arn:aws:iam::999888777666:role/TestRole"
			resolved := map[string]*ResolvedPermissions{
				principal: {
					PrincipalARN:   principal,
					EffectiveAllow: tt.identityAllow,
				},
			}

			idx := access.NewResourceAccessIndex()
			for _, g := range tt.resourceGrants {
				for _, action := range g.actions {
					idx.AddEntry(asset.ID(g.resourceARN), access.ResourceAccessEntry{
						PrincipalARN:   principal,
						Actions:        []string{action},
						IsCrossAccount: g.isCrossAccount,
						IsPublic:       g.isPublic,
						GrantSource:    g.resourceARN,
					})
				}
			}

			applyResourcePolicyGrants(resolved, idx)

			var totalActions int
			for _, rpg := range resolved[principal].ResourcePolicyGrants {
				totalActions += len(rpg.Actions)
			}
			if totalActions != tt.wantActions {
				t.Errorf("got %d resource policy grant actions, want %d", totalActions, tt.wantActions)
			}
		})
	}
}
