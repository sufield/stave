package acl

import "testing"

func TestAnalyze_PublicAndAuthenticatedGrants(t *testing.T) {
	grants := []Grant{
		{Grantee: AllUsersGranteeURI, Permission: "READ"},
		{Grantee: AuthenticatedUsersGranteeURI, Permission: "FULL_CONTROL"},
	}

	got := Analyze(grants)

	if !got.AllowsPublicRead {
		t.Fatal("expected public read to be allowed")
	}
	if got.AllowsPublicWrite {
		t.Fatal("expected public write to be false for authenticated-only full control")
	}
	if !got.AllowsAuthenticatedRead {
		t.Fatal("expected authenticated read to be allowed")
	}
	if !got.AllowsAuthenticatedWrite {
		t.Fatal("expected authenticated write to be allowed via full control")
	}
	if got.HasFullControlPublic {
		t.Fatal("expected full control public to remain false")
	}
	if !got.HasFullControlAuthenticated {
		t.Fatal("expected full control authenticated to be true")
	}
}

func TestAnalyze_ACLPermissions(t *testing.T) {
	grants := []Grant{
		{Grantee: AllUsersGranteeURI, Permission: "WRITE_ACP"},
		{Grantee: AuthenticatedUsersGranteeURI, Permission: "READ_ACP"},
	}

	got := Analyze(grants)

	if !got.AllowsPublicACLWrite {
		t.Fatal("expected public ACL write to be allowed")
	}
	if !got.AllowsAuthenticatedACLRead {
		t.Fatal("expected authenticated ACL read to be allowed")
	}
}

func TestIsPublicGrantee(t *testing.T) {
	if !IsPublicGrantee(AllUsersGranteeURI) {
		t.Fatal("expected all-users URI to be public")
	}
	if !IsPublicGrantee(AuthenticatedUsersGranteeURI) {
		t.Fatal("expected authenticated-users URI to be public")
	}
	if IsPublicGrantee("http://example.com/private") {
		t.Fatal("expected non-AWS group URI to be non-public")
	}
}
