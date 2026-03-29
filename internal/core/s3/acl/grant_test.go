package acl

import (
	"testing"

	"github.com/sufield/stave/internal/core/evaluation/risk"
)

func TestAudience_String(t *testing.T) {
	tests := []struct {
		aud  Audience
		want string
	}{
		{AudiencePrivate, "private"},
		{AudienceAllUsers, "all_users"},
		{AudienceAuthenticatedOnly, "authenticated"},
		{Audience(99), "private"}, // unknown defaults to private
	}
	for _, tt := range tests {
		if got := tt.aud.String(); got != tt.want {
			t.Errorf("Audience(%d).String() = %q, want %q", tt.aud, got, tt.want)
		}
	}
}

func TestAudience_MarshalText(t *testing.T) {
	tests := []struct {
		aud  Audience
		want string
	}{
		{AudiencePrivate, "private"},
		{AudienceAllUsers, "all_users"},
		{AudienceAuthenticatedOnly, "authenticated"},
	}
	for _, tt := range tests {
		data, err := tt.aud.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText() error: %v", err)
		}
		if string(data) != tt.want {
			t.Errorf("MarshalText() = %q, want %q", data, tt.want)
		}
	}
}

func TestAudience_UnmarshalText(t *testing.T) {
	tests := []struct {
		input string
		want  Audience
	}{
		{"all_users", AudienceAllUsers},
		{"public", AudienceAllUsers},
		{"ALL_USERS", AudienceAllUsers},
		{"authenticated", AudienceAuthenticatedOnly},
		{"auth", AudienceAuthenticatedOnly},
		{"private", AudiencePrivate},
	}
	for _, tt := range tests {
		var a Audience
		if err := a.UnmarshalText([]byte(tt.input)); err != nil {
			t.Fatalf("UnmarshalText(%q) error: %v", tt.input, err)
		}
		if a != tt.want {
			t.Errorf("UnmarshalText(%q) = %d, want %d", tt.input, a, tt.want)
		}
	}

	t.Run("invalid", func(t *testing.T) {
		var a Audience
		if err := a.UnmarshalText([]byte("invalid")); err == nil {
			t.Error("expected error for invalid audience")
		}
	})
}

func TestGrant_Audience(t *testing.T) {
	tests := []struct {
		name    string
		grantee string
		want    Audience
	}{
		{"empty", "", AudiencePrivate},
		{"all users suffix /", GroupAllUsers, AudienceAllUsers},
		{"all users colon suffix", "http://example.com:AllUsers", AudienceAllUsers},
		{"authenticated users suffix /", GroupAuthenticatedUsers, AudienceAuthenticatedOnly},
		{"authenticated users colon suffix", "http://example.com:AuthenticatedUsers", AudienceAuthenticatedOnly},
		{"canonical user id", "1234567890abcdef", AudiencePrivate},
		{"case insensitive", "http://acs.amazonaws.com/groups/global/ALLUSERS", AudienceAllUsers},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := Grant{Grantee: tt.grantee}
			if got := g.Audience(); got != tt.want {
				t.Errorf("Audience() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGrant_IsPublic(t *testing.T) {
	tests := []struct {
		grantee string
		want    bool
	}{
		{GroupAllUsers, true},
		{GroupAuthenticatedUsers, true},
		{"private-id", false},
		{"", false},
	}
	for _, tt := range tests {
		g := Grant{Grantee: tt.grantee}
		if got := g.IsPublic(); got != tt.want {
			t.Errorf("Grant{%q}.IsPublic() = %v, want %v", tt.grantee, got, tt.want)
		}
	}
}

func TestGrant_HasFullControl(t *testing.T) {
	tests := []struct {
		perm string
		want bool
	}{
		{"FULL_CONTROL", true},
		{"full_control", true},
		{"READ", false},
		{"WRITE", false},
		{"", false},
	}
	for _, tt := range tests {
		g := Grant{Permission: ACLPermission(tt.perm)}
		if got := g.HasFullControl(); got != tt.want {
			t.Errorf("HasFullControl(%q) = %v, want %v", tt.perm, got, tt.want)
		}
	}
}

func TestGrant_Permissions(t *testing.T) {
	tests := []struct {
		perm ACLPermission
		want risk.Permission
	}{
		{ACLPermRead, risk.PermRead},
		{ACLPermWrite, risk.PermWrite},
		{ACLPermReadACP, risk.PermAdminRead},
		{ACLPermWriteACP, risk.PermAdminWrite},
		{ACLPermFullControl, risk.PermRead | risk.PermWrite | risk.PermAdminRead | risk.PermAdminWrite},
		{ACLPermission("UNKNOWN"), 0},
		{ACLPermission(""), 0},
		{ACLPermission("  read  "), risk.PermRead}, // whitespace handling
	}
	for _, tt := range tests {
		g := Grant{Permission: tt.perm}
		if got := g.Permissions(); got != tt.want {
			t.Errorf("Permissions(%q) = %v, want %v", tt.perm, got, tt.want)
		}
	}
}

func TestNew_DefensiveCopy(t *testing.T) {
	original := []Grant{
		{Grantee: GroupAllUsers, Permission: ACLPermRead},
	}
	list := New(original)

	// Mutate the original
	original[0].Permission = ACLPermFullControl

	// List should still have READ
	assessment := list.Assess()
	if assessment.Permissions[AudienceAllUsers].Has(risk.PermWrite) {
		t.Error("defensive copy failed: mutation leaked")
	}
}

func TestAssess_PrivateOnly(t *testing.T) {
	grants := []Grant{
		{Grantee: "canonical-user-id", Permission: ACLPermFullControl},
	}
	assessment := Assess(grants)
	if len(assessment.Permissions) != 0 {
		t.Errorf("expected no public permissions, got %v", assessment.Permissions)
	}
	if len(assessment.PublicGrantees) != 0 {
		t.Errorf("expected no public grantees, got %v", assessment.PublicGrantees)
	}
}

func TestAssess_PublicGranteesTracked(t *testing.T) {
	grants := []Grant{
		{Grantee: GroupAllUsers, Permission: ACLPermRead},
		{Grantee: GroupAllUsers, Permission: ACLPermWrite},
	}
	assessment := Assess(grants)
	if len(assessment.PublicGrantees) != 2 {
		t.Errorf("expected 2 public grantees, got %d", len(assessment.PublicGrantees))
	}
}

func TestIsPublicGrantee_EdgeCases(t *testing.T) {
	tests := []struct {
		uri  string
		want bool
	}{
		{"", false},
		{"http://example.com/AllUsers", true},
		{"http://example.com/AuthenticatedUsers", true},
		{"http://example.com/allusers", true},
		{"AllUsers", false}, // no prefix path
	}
	for _, tt := range tests {
		if got := IsPublicGrantee(tt.uri); got != tt.want {
			t.Errorf("IsPublicGrantee(%q) = %v, want %v", tt.uri, got, tt.want)
		}
	}
}
