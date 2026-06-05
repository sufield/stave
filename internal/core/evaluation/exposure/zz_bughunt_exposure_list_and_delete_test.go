package exposure

import "testing"

// TestBugHunt_LatentPublicList_HonorsResourceSource proves that a
// resource-policy public-list grant that is suppressed downstream by the
// resource-bound guardrail is still flagged as latent.
//
// resolution.go:62 computes LatentPublicList from identity.Public.List only,
// ignoring resource.Public.List. The sibling LatentPublicRead (line 21-22)
// honors BOTH identity and resource sources. With BlockResourceBoundPublicAccess
// set, resolveMask drops the resource perms so resolved.List is false; the
// resource-side public-list grant is therefore suppressed but should still be
// reported as latent reachability ("shadow exposure").
func TestBugHunt_LatentPublicList_HonorsResourceSource(t *testing.T) {
	identity := Visibility{} // no identity grant
	resource := Visibility{
		Public: Capabilities{List: true}, // resource-policy public list grant
	}
	gov := GovernanceOverrides{
		BlockResourceBoundPublicAccess: true, // suppresses the resource grant
	}

	exposure := BuildResourceExposure(identity, resource, gov)

	// The grant is suppressed: not effectively public-list.
	if exposure.PublicList {
		t.Fatalf("precondition: resource public-list should be suppressed by guardrail, got PublicList=true")
	}
	// ...but it must be flagged as latent (would re-activate if guardrail lifted).
	if !exposure.LatentPublicList {
		t.Errorf("resource-policy public-list suppressed by guardrail should be LatentPublicList=true, got false")
	}
}

// TestBugHunt_IsPubliclyExposed_IncludesDelete proves that a resource that is
// publicly deletable (but not public-read/write/list/admin) is reported as
// publicly exposed.
//
// reachability.go:54 omits e.PublicDelete from the disjunction even though
// PublicDelete is a first-class field populated from resolved.Delete. A bucket
// policy granting only s3:DeleteObject to "*" therefore wrongly reports NOT
// publicly exposed.
func TestBugHunt_IsPubliclyExposed_IncludesDelete(t *testing.T) {
	e := &ResourceExposure{PublicDelete: true}
	if !e.IsPubliclyExposed() {
		t.Error("PublicDelete=true should be publicly exposed")
	}
}
