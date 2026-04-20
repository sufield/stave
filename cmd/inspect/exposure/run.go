package exposure

import (
	"encoding/json"
	"fmt"
	"io"

	domainexposure "github.com/sufield/stave/internal/core/evaluation/exposure"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// Payload is the JSON input shape the command parses from file or stdin.
type Payload struct {
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

// ToDomain converts the CLI input into the domain's NormalizedResourceInput.
func (r ResourceInput) ToDomain() domainexposure.NormalizedResourceInput {
	tracker := domainexposure.NewEvidenceTracker()
	for _, ev := range []struct {
		cat  domainexposure.EvidenceCategory
		path string
	}{
		{domainexposure.EvIdentityRead, "input.identity_perms"},
		{domainexposure.EvResourceRead, "input.resource_perms"},
		{domainexposure.EvIdentityWrite, "input.identity_perms"},
		{domainexposure.EvResourceWrite, "input.resource_perms"},
		{domainexposure.EvDiscovery, "input.resource_perms"},
		{domainexposure.EvResourceAdminRead, "input.resource_perms"},
		{domainexposure.EvDelete, "input.resource_perms"},
	} {
		tracker.Record(ev.cat, []string{ev.path})
	}

	return domainexposure.NormalizedResourceInput{
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
	}
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
	HasWildcardPrincipal  bool     `json:"has_wildcard_principal"`
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

// Output is the JSON output.
type Output struct {
	Classifications []domainexposure.Classification  `json:"classifications"`
	BucketAccess    *domainexposure.BucketAccess     `json:"bucket_access,omitempty"`
	Visibility      *domainexposure.ResourceExposure `json:"visibility,omitempty"`
}

// Input is the per-run payload assembled at the RunE boundary.
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

	var payload Payload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("parse exposure input: %w", err)
	}

	// Transform input to domain types.
	resources := make([]domainexposure.NormalizedResourceInput, len(payload.Resources))
	for i, r := range payload.Resources {
		resources[i] = r.ToDomain()
	}

	// Classify exposure.
	output := Output{
		Classifications: domainexposure.ClassifyExposure(resources),
	}

	// Resolve bucket access if access input provided.
	if payload.Access != nil {
		a := payload.Access
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

		vis := domainexposure.BuildResourceExposure(identity, resource, gov)
		output.Visibility = &vis

		bucketAccess := domainexposure.ResolveBucketAccess(domainexposure.BucketAccessInput{
			Identity:             identity,
			Resource:             resource,
			Gov:                  gov,
			HasWildcardPrincipal: a.HasWildcardPrincipal,
			CrossAccount: domainexposure.CrossAccountAccess{
				HasExternalAccess: a.HasExternalAccess,
				HasExternalWrite:  a.HasExternalWrite,
			},
		})
		output.BucketAccess = &bucketAccess
	}

	enc := json.NewEncoder(in.Stdout)
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
