package stave

import (
	"bytes"
	"encoding/json"
	"fmt"

	domainexposure "github.com/sufield/stave/internal/core/evaluation/exposure"
)

type exposurePayload struct {
	Resources []exposureResourceInput `json:"resources"`
	Access    *exposureAccessInput    `json:"access,omitempty"`
}

type exposureResourceInput struct {
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

func (r exposureResourceInput) toDomain() domainexposure.NormalizedResourceInput {
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

type exposureAccessInput struct {
	IdentityPublic        exposureCapInput `json:"identity_public"`
	IdentityAuthenticated exposureCapInput `json:"identity_authenticated"`
	ResourcePublic        exposureCapInput `json:"resource_public"`
	ResourceAuthenticated exposureCapInput `json:"resource_authenticated"`
	BlockResourcePublic   bool             `json:"block_resource_public"`
	BlockIdentityPublic   bool             `json:"block_identity_public"`
	EnforceStrict         bool             `json:"enforce_strict"`
	HasWildcardPrincipal  bool             `json:"has_wildcard_principal"`
	HasExternalAccess     bool             `json:"has_external_access"`
	HasExternalWrite      bool             `json:"has_external_write"`
}

type exposureCapInput struct {
	Read   bool `json:"read"`
	Write  bool `json:"write"`
	List   bool `json:"list"`
	Delete bool `json:"delete"`
	Admin  bool `json:"admin"`
}

type exposureOutput struct {
	Classifications []domainexposure.Classification  `json:"classifications"`
	BucketAccess    *domainexposure.BucketAccess     `json:"bucket_access,omitempty"`
	Visibility      *domainexposure.ResourceExposure `json:"visibility,omitempty"`
}

func toExposureCaps(c exposureCapInput) domainexposure.Capabilities {
	return domainexposure.Capabilities{
		Read:   c.Read,
		Write:  c.Write,
		List:   c.List,
		Delete: c.Delete,
		Admin:  c.Admin,
	}
}

// InspectExposure parses an exposure-classification input (JSON), runs
// the exposure engine — classification plus optional bucket-access and
// visibility resolution — and returns the result as indented JSON bytes
// (HTML-escaped, one trailing newline, matching the prior json.Encoder
// output). It is the library entry point behind `stave inspect exposure`.
func InspectExposure(data []byte) ([]byte, error) {
	var payload exposurePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("parse exposure input: %w", err)
	}

	resources := make([]domainexposure.NormalizedResourceInput, len(payload.Resources))
	for i, r := range payload.Resources {
		resources[i] = r.toDomain()
	}

	output := exposureOutput{
		Classifications: domainexposure.ClassifyExposure(resources),
	}

	if payload.Access != nil {
		a := payload.Access
		identity := domainexposure.Visibility{
			Public:        toExposureCaps(a.IdentityPublic),
			Authenticated: toExposureCaps(a.IdentityAuthenticated),
		}
		resource := domainexposure.Visibility{
			Public:        toExposureCaps(a.ResourcePublic),
			Authenticated: toExposureCaps(a.ResourceAuthenticated),
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

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		return nil, fmt.Errorf("encode exposure output: %w", err)
	}
	return buf.Bytes(), nil
}
