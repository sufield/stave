package exposure

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

const (
	// Canonical exposure classification IDs (Cloud Neutral).
	idResourceTakeover    kernel.ControlID = "CTL.STORAGE.TAKEOVER.001"
	idWebPublic           kernel.ControlID = "CTL.STORAGE.WEBSITE.PUBLIC.001"
	idAuthenticatedRead   kernel.ControlID = "CTL.STORAGE.GLOBAL.AUTHENTICATED.READ.001"
	idPublicRead          kernel.ControlID = "CTL.STORAGE.PUBLIC.READ.001"
	idResourcePublicRead  kernel.ControlID = "CTL.STORAGE.RESOURCE.PUBLIC.READ.001"
	idPublicList          kernel.ControlID = "CTL.STORAGE.PUBLIC.LIST.001"
	idPublicWrite         kernel.ControlID = "CTL.STORAGE.PUBLIC.WRITE.001"
	idResourcePublicWrite kernel.ControlID = "CTL.STORAGE.RESOURCE.PUBLIC.WRITE.001"
	idPublicAdminRead     kernel.ControlID = "CTL.STORAGE.PUBLIC.ADMIN.READ.001"
	idPublicAdminWrite    kernel.ControlID = "CTL.STORAGE.PUBLIC.ADMIN.WRITE.001"
	idPublicDelete        kernel.ControlID = "CTL.STORAGE.PUBLIC.DELETE.001"
)

// ValidateControlIDs checks that all hardcoded exposure control ID constants
// conform to the required format. Call this during bootstrap instead of
// relying on init()-time panics.
func ValidateControlIDs() error {
	ids := []kernel.ControlID{
		idResourceTakeover, idWebPublic, idAuthenticatedRead, idPublicRead,
		idResourcePublicRead, idPublicList, idPublicWrite, idResourcePublicWrite,
		idPublicAdminRead, idPublicAdminWrite, idPublicDelete,
	}
	for _, id := range ids {
		if err := kernel.ValidateControlIDFormat(id.String()); err != nil {
			return fmt.Errorf("invalid exposure control ID %q: %w", id, err)
		}
	}
	return nil
}

// ClassifyExposure evaluates a set of normalized resource states and returns
// classified risk findings.
func ClassifyExposure(resources []NormalizedResourceInput) []ExposureClassification {
	if len(resources) == 0 {
		return nil
	}

	var findings []ExposureClassification
	for _, r := range resources {
		findings = append(findings, classifyResource(r)...)
	}

	// Sort findings deterministically: by Resource ID, then by Control ID severity.
	slices.SortFunc(findings, func(a, b ExposureClassification) int {
		if a.Resource != b.Resource {
			return strings.Compare(a.Resource, b.Resource)
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})

	return findings
}

func classifyResource(r NormalizedResourceInput) []ExposureClassification {
	// 1. Check for Resource Takeover (Dangling Reference)
	if !r.Exists && r.ExternalReference {
		return []ExposureClassification{{
			ID:             idResourceTakeover,
			Resource:       r.Name,
			ExposureType:   TypeResourceTakeover,
			PrincipalScope: kernel.ScopeNotApplicable,
			Actions:        []string{},
			EvidencePath:   []string{"resource.exists", "resource.external_reference"},
		}}
	}

	// 2. Build Analysis Context
	ctx := resolutionContext{
		input:         r,
		identityPerms: capabilitySetFromMask(r.IdentityPerms),
		resourcePerms: capabilitySetFromMask(r.ResourcePerms),
		isAuthOnly:    r.IsAuthenticatedOnly,
		evidence:      r.Evidence,
		writeSourceStat: writeSourceMetadata{
			CanAlsoRead: r.WriteSourceHasGet,
			CanAlsoList: r.WriteSourceHasList,
		},
	}

	// 3. Resolve Risks across different capability axes
	var findings []ExposureClassification
	findings = append(findings, ctx.resolveRead()...)
	findings = append(findings, ctx.resolveList()...)
	findings = append(findings, ctx.resolveWrite()...)
	findings = append(findings, ctx.resolveAdministrative()...)

	return findings
}
