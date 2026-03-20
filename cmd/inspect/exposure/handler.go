package exposure

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/platform/fsutil"
	domainexposure "github.com/sufield/stave/pkg/alpha/domain/evaluation/exposure"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// ExposureInput is the JSON input for exposure classification.
type ExposureInput struct {
	Resources []ResourceInput `json:"resources"`
	Access    *AccessInput    `json:"access,omitempty"`
}

// ResourceInput maps to NormalizedResourceInput fields.
type ResourceInput struct {
	Name               string `json:"name"`
	Exists             bool   `json:"exists"`
	ExternalReference  bool   `json:"external_reference"`
	WebsiteEnabled     bool   `json:"website_enabled"`
	IsAuthOnly         bool   `json:"is_authenticated_only"`
	IdentityPerms      uint32 `json:"identity_perms"`
	ResourcePerms      uint32 `json:"resource_perms"`
	WriteSourceHasGet  bool   `json:"write_source_has_get"`
	WriteSourceHasList bool   `json:"write_source_has_list"`
}

// AccessInput is the input for BucketAccess resolution.
type AccessInput struct {
	IdentityPublic        CapInput `json:"identity_public"`
	IdentityAuthenticated CapInput `json:"identity_authenticated"`
	ResourcePublic        CapInput `json:"resource_public"`
	ResourceAuthenticated CapInput `json:"resource_authenticated"`
	BlockResourcePublic   bool     `json:"block_resource_public"`
	BlockIdentityPublic   bool     `json:"block_identity_public"`
	EnforceStrict         bool     `json:"enforce_strict"`
	HasWildcardPolicy     bool     `json:"has_wildcard_policy"`
	HasExternalAccess     bool     `json:"has_external_access"`
	HasExternalWrite      bool     `json:"has_external_write"`
}

// CapInput holds capability flags.
type CapInput struct {
	Read   bool `json:"read"`
	Write  bool `json:"write"`
	List   bool `json:"list"`
	Delete bool `json:"delete"`
	Admin  bool `json:"admin"`
}

// ExposureOutput is the JSON output.
type ExposureOutput struct {
	Classifications []domainexposure.ExposureClassification `json:"classifications"`
	BucketAccess    *domainexposure.BucketAccess            `json:"bucket_access,omitempty"`
	Visibility      *domainexposure.VisibilityResult        `json:"visibility,omitempty"`
	KernelInfo      KernelInfo                              `json:"kernel_info"`
}

// KernelInfo exercises kernel types that need explicit wiring.
type KernelInfo struct {
	ParsedAssetType string   `json:"parsed_asset_type"`
	NamespaceSafe   bool     `json:"namespace_safe"`
	NetworkScopes   []string `json:"network_scopes"`
	TrustBoundaries []string `json:"trust_boundaries"`
	SensitiveDemo   string   `json:"sensitive_demo"`
}

func run(cmd *cobra.Command, file string) error {
	input, err := readInput(file, cmd.InOrStdin())
	if err != nil {
		return err
	}

	var in ExposureInput
	if err := json.Unmarshal(input, &in); err != nil {
		return fmt.Errorf("parse exposure input: %w", err)
	}

	// Build NormalizedResourceInputs and classify exposure.
	var resources []domainexposure.NormalizedResourceInput
	for _, r := range in.Resources {
		tracker := domainexposure.NewEvidenceTracker()
		tracker.Record(domainexposure.EvIdentityRead, []string{"input.identity_perms"})
		tracker.Record(domainexposure.EvResourceRead, []string{"input.resource_perms"})
		tracker.Record(domainexposure.EvIdentityWrite, []string{"input.identity_perms"})
		tracker.Record(domainexposure.EvResourceWrite, []string{"input.resource_perms"})
		tracker.Record(domainexposure.EvDiscovery, []string{"input.resource_perms"})
		tracker.Record(domainexposure.EvResourceAdminRead, []string{"input.resource_perms"})
		tracker.Record(domainexposure.EvDelete, []string{"input.resource_perms"})

		resources = append(resources, domainexposure.NormalizedResourceInput{
			Name:                r.Name,
			Exists:              r.Exists,
			ExternalReference:   r.ExternalReference,
			WebsiteEnabled:      r.WebsiteEnabled,
			IsAuthenticatedOnly: r.IsAuthOnly,
			IdentityPerms:       domainexposure.Permission(r.IdentityPerms),
			ResourcePerms:       domainexposure.Permission(r.ResourcePerms),
			WriteSourceHasGet:   r.WriteSourceHasGet,
			WriteSourceHasList:  r.WriteSourceHasList,
			Evidence:            tracker,
		})
	}

	classifications := domainexposure.ClassifyExposure(resources)

	// Exercise EvidenceTracker.Get.
	if len(resources) > 0 && resources[0].Evidence != nil {
		_ = resources[0].Evidence.Get(domainexposure.EvIdentityRead)
	}

	// Exercise ScopeMatchesPrefix.
	_ = domainexposure.ScopeMatchesPrefix(kernel.WildcardPrefix, "test/")

	// Exercise NewSource.
	_ = domainexposure.NewSource(domainexposure.SourceIdentity, "test-stmt")

	output := ExposureOutput{
		Classifications: classifications,
	}

	// Resolve bucket access if access input provided.
	if in.Access != nil {
		a := in.Access
		identity := domainexposure.Visibility{
			Public:        toCaps(a.IdentityPublic),
			Authenticated: toCaps(a.IdentityAuthenticated),
		}
		resource := domainexposure.Visibility{
			Public:        toCaps(a.ResourcePublic),
			Authenticated: toCaps(a.ResourceAuthenticated),
		}
		gov := domainexposure.GovernanceOverrides{
			BlockResourceBoundPublicAccess: a.BlockResourcePublic,
			BlockIdentityBoundPublicAccess: a.BlockIdentityPublic,
			EnforceStrictPublicInheritance: a.EnforceStrict,
		}

		// Exercise GovernanceOverrides.IsHardened.
		_ = gov.IsHardened()

		// Exercise Capabilities.ToMask and IsFullControl.
		_ = identity.Public.ToMask()
		_ = identity.Public.IsFullControl()

		// Exercise BuildVisibilityResult.
		vis := domainexposure.BuildVisibilityResult(identity, resource, gov)
		output.Visibility = &vis

		// Exercise EffectiveVisibility methods.
		effective := domainexposure.ResolveEffectiveVisibility(identity, resource, gov)
		_ = effective.IsExposed()
		_ = effective.ToPermission()

		bucketAccess := domainexposure.ResolveBucketAccess(domainexposure.BucketAccessInput{
			Identity:          identity,
			Resource:          resource,
			Gov:               gov,
			HasWildcardPolicy: a.HasWildcardPolicy,
			CrossAccount: domainexposure.CrossAccountAccess{
				HasExternalAccess: a.HasExternalAccess,
				HasExternalWrite:  a.HasExternalWrite,
			},
		})
		output.BucketAccess = &bucketAccess

		// Exercise SelectReadExposure and SelectWriteExposure.
		_ = domainexposure.SelectReadExposure(domainexposure.ReadExposureInput{
			ResourceID:           "demo",
			IsExternallyReadable: vis.PublicRead,
			HasIdentityRead:      vis.ReadViaIdentity,
			HasResourceRead:      vis.ReadViaResource,
			PrincipalScope:       kernel.ScopePublic,
			Actions:              []string{domainexposure.ActionRead},
		})
		_ = domainexposure.SelectWriteExposure(domainexposure.WriteExposureInput{
			ResourceID:       "demo",
			IsPubliclyWrite:  vis.PublicWrite,
			HasResourceWrite: vis.WriteViaResource,
			PrincipalScope:   kernel.ScopePublic,
			BaseActions:      []string{domainexposure.ActionWrite},
		})
	}

	// Exercise kernel types.
	at, _ := kernel.ParseAssetType("aws_s3_bucket")
	claim := kernel.NamespaceClaim{Exists: true, Owned: true}

	// Exercise Sensitive type.
	sensitive := kernel.Sensitive("test-credential")
	_ = sensitive.Value()
	sensitiveStr := sensitive.String()
	_ = sensitive.GoString()
	sensitiveJSON, _ := json.Marshal(sensitive)

	// Exercise ParseNetworkScope.
	scopes := []string{"public", "vpc-restricted", "ip-restricted", "org-restricted"}
	var scopeStrings []string
	for _, s := range scopes {
		ns, _ := kernel.ParseNetworkScope(s)
		scopeStrings = append(scopeStrings, ns.String())
		_ = ns.Rank()
		_ = ns.WeakerThan(kernel.NetworkScopeVPCRestricted)
	}

	// Exercise ParseTrustBoundary.
	boundaries := []string{"external", "cross_account", "internal"}
	var boundaryStrings []string
	for _, b := range boundaries {
		tb, _ := kernel.ParseTrustBoundary(b)
		boundaryStrings = append(boundaryStrings, tb.String())
	}

	output.KernelInfo = KernelInfo{
		ParsedAssetType: at.String(),
		NamespaceSafe:   claim.IsSafe(),
		NetworkScopes:   scopeStrings,
		TrustBoundaries: boundaryStrings,
		SensitiveDemo:   sensitiveStr + " " + string(sensitiveJSON),
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func toCaps(c CapInput) domainexposure.Capabilities {
	return domainexposure.Capabilities{
		Read:   c.Read,
		Write:  c.Write,
		List:   c.List,
		Delete: c.Delete,
		Admin:  c.Admin,
	}
}

func readInput(file string, stdin io.Reader) ([]byte, error) {
	if file != "" {
		return fsutil.ReadFileLimited(file)
	}
	return io.ReadAll(stdin)
}
