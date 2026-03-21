package acl

import (
	"testing"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
)

func TestAssess_PublicAndAuthenticatedGrants(t *testing.T) {
	grants := []Grant{
		{Grantee: allUsersURI, Permission: "READ"},
		{Grantee: authenticatedUsersURI, Permission: "FULL_CONTROL"},
	}

	got := Assess(grants)

	if !got.Permissions[AudienceAllUsers].Overlap(risk.PermRead) {
		t.Fatal("expected public read to be allowed")
	}
	if got.Permissions[AudienceAllUsers].Overlap(risk.PermWrite) {
		t.Fatal("expected public write to be false for authenticated-only full control")
	}
	if !got.Permissions[AudienceAuthenticatedOnly].Overlap(risk.PermRead) {
		t.Fatal("expected authenticated read to be allowed")
	}
	if !got.Permissions[AudienceAuthenticatedOnly].Overlap(risk.PermWrite) {
		t.Fatal("expected authenticated write to be allowed via full control")
	}
	if !got.Permissions[AudienceAuthenticatedOnly].Has(risk.PermRead | risk.PermWrite | risk.PermAdminRead | risk.PermAdminWrite) {
		t.Fatal("expected authenticated to have all four ACL permission bits via full control")
	}
}

func TestAssess_ACLPermissions(t *testing.T) {
	grants := []Grant{
		{Grantee: allUsersURI, Permission: "WRITE_ACP"},
		{Grantee: authenticatedUsersURI, Permission: "READ_ACP"},
	}

	got := Assess(grants)

	if !got.Permissions[AudienceAllUsers].Overlap(risk.PermAdminWrite) {
		t.Fatal("expected public ACL write to be allowed")
	}
	if !got.Permissions[AudienceAuthenticatedOnly].Overlap(risk.PermAdminRead) {
		t.Fatal("expected authenticated ACL read to be allowed")
	}
}

func TestIsPublicGrantee(t *testing.T) {
	if !IsPublicGrantee(allUsersURI) {
		t.Fatal("expected all-users URI to be public")
	}
	if !IsPublicGrantee(authenticatedUsersURI) {
		t.Fatal("expected authenticated-users URI to be public")
	}
	if IsPublicGrantee("http://example.com/private") {
		t.Fatal("expected non-AWS group URI to be non-public")
	}
}
