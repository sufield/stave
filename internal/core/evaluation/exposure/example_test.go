package exposure_test

import (
	"fmt"

	"github.com/sufield/stave/internal/core/evaluation/exposure"
	"github.com/sufield/stave/internal/core/kernel"
)

func ExampleClassifyExposure() {
	tracker := exposure.NewEvidenceTracker()
	tracker.Record(exposure.EvIdentityRead, []string{"policy.statement[0]"})
	tracker.Record(exposure.EvDiscovery, []string{"policy.statement[0]"})

	resources := []exposure.NormalizedResourceInput{{
		Name:          "my-bucket",
		Exists:        true,
		IdentityPerms: exposure.PermRead | exposure.PermList,
		Evidence:      tracker,
	}}

	findings := exposure.ClassifyExposure(resources)
	for _, f := range findings {
		fmt.Printf("%s: %s (%s)\n", f.ID, f.ExposureType, f.PrincipalScope)
	}
	// Output:
	// CTL.STORAGE.PUBLIC.LIST.001: public_list (public)
	// CTL.STORAGE.PUBLIC.READ.001: public_read (public)
}

func ExampleBuildVisibilityResult() {
	identity := exposure.Visibility{
		Public: exposure.Capabilities{Read: true, List: true},
	}
	resource := exposure.Visibility{}
	gov := exposure.GovernanceOverrides{
		BlockIdentityBoundPublicAccess: true,
	}

	vis := exposure.BuildVisibilityResult(identity, resource, gov)
	fmt.Println("public_read:", vis.PublicRead)
	fmt.Println("latent_public_read:", vis.LatentPublicRead)
	// Output:
	// public_read: false
	// latent_public_read: true
}

func ExampleResolveBucketAccess() {
	access := exposure.ResolveBucketAccess(exposure.BucketAccessInput{
		Identity: exposure.Visibility{
			Public: exposure.Capabilities{Read: true},
		},
		CrossAccount: exposure.CrossAccountAccess{
			HasExternalAccess: true,
		},
	})
	fmt.Println("scope:", access.Scope)
	fmt.Println("trust_boundary:", access.TrustBoundary)

	_ = kernel.NetworkScopePublic // ensure kernel is importable alongside exposure
	// Output:
	// scope: public
	// trust_boundary: external
}
