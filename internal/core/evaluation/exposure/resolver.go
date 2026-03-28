package exposure

import (
	"github.com/sufield/stave/internal/core/kernel"
)

// Constants for normalized domain actions.
// These are mapped to vendor-specific strings only at the output/adapter layer.
const (
	ActionRead       = "Read"
	ActionWrite      = "Write"
	ActionList       = "List"
	ActionDelete     = "Delete"
	ActionAdminRead  = "AdminRead"
	ActionAdminWrite = "AdminWrite"
)

// effectivePerms combines permissions from all sources (Identity and Resource).
func (c *resolutionContext) effectivePerms() Permission {
	return c.identityPerms.ToMask() | c.resourcePerms.ToMask()
}

// principalScope determines if the exposure is truly public or restricted to authenticated users.
func (c *resolutionContext) principalScope() kernel.PrincipalScope {
	if c.isAuthOnly {
		return kernel.ScopeAuthenticated
	}
	return kernel.ScopePublic
}

// readEvidence finds the most relevant evidence path for a read exposure.
func (c *resolutionContext) readEvidence() []string {
	if ev := c.evidence.Get(EvIdentityRead); len(ev) > 0 {
		return ev
	}
	return c.evidence.Get(EvResourceRead)
}

// writeScope classifies the severity of write access.
func (c *resolutionContext) writeScope() WriteScope {
	perms := c.effectivePerms()
	if !perms.Has(PermWrite) {
		return ""
	}
	if perms.Has(PermRead) || perms.Has(PermList) {
		return WriteScopeFull
	}
	return WriteScopeBlind
}

// resolveRead evaluates and selects the primary read-based exposure finding.
func (c *resolutionContext) resolveRead() []ExposureClassification {
	perms := c.effectivePerms()

	writeAbsorbsRead := perms.Has(PermWrite) &&
		c.identityPerms.Write &&
		c.writeSourceStat.CanAlsoRead

	selected := SelectReadExposure(ReadExposureInput{
		ResourceID:           c.input.Name,
		WebHostingEnabled:    c.input.WebsiteEnabled,
		IsExternallyReadable: perms.Has(PermRead),
		WriteAbsorbsRead:     writeAbsorbsRead,
		IsAuthenticatedOnly:  c.isAuthOnly,
		HasIdentityRead:      c.identityPerms.Read,
		HasResourceRead:      c.resourcePerms.Read,
		PrincipalScope:       c.principalScope(),
		EvidenceGeneral:      c.readEvidence(),
		EvidenceIdentity:     c.evidence.Get(EvIdentityRead),
		EvidenceResource:     c.evidence.Get(EvResourceRead),
		Actions:              []string{ActionRead},
	})

	if selected == nil {
		return nil
	}
	return []ExposureClassification{selected.finding}
}

// resolveList evaluates findings specifically for resource discovery (listing).
func (c *resolutionContext) resolveList() []ExposureClassification {
	if !c.effectivePerms().Has(PermList) {
		return nil
	}
	return []ExposureClassification{{
		ID:             idPublicList,
		Resource:       c.input.Name,
		ExposureType:   TypePublicList,
		PrincipalScope: c.principalScope(),
		Actions:        []string{ActionList},
		EvidencePath:   c.evidence.Get(EvDiscovery),
	}}
}

// resolveWrite evaluates and selects the primary write-based exposure finding.
func (c *resolutionContext) resolveWrite() []ExposureClassification {
	perms := c.effectivePerms()
	selected := SelectWriteExposure(WriteExposureInput{
		ResourceID:       c.input.Name,
		IsPubliclyWrite:  perms.Has(PermWrite),
		HasIdentityWrite: c.identityPerms.Write,
		HasResourceWrite: c.resourcePerms.Write,
		PrincipalScope:   c.principalScope(),
		WriteScope:       c.writeScope(),
		EvidenceIdentity: c.evidence.Get(EvIdentityWrite),
		EvidenceResource: c.evidence.Get(EvResourceWrite),
		CanAlsoRead:      c.writeSourceStat.CanAlsoRead,
		CanAlsoList:      c.writeSourceStat.CanAlsoList,
		BaseActions:      []string{ActionWrite},
	})

	if selected == nil {
		return nil
	}
	return []ExposureClassification{selected.finding}
}

// resolveAdministrative evaluates findings for management-plane exposures (Delete/Metadata).
func (c *resolutionContext) resolveAdministrative() []ExposureClassification {
	perms := c.effectivePerms()
	scope := c.principalScope()
	findings := make([]ExposureClassification, 0, 3)

	if perms.Has(PermMetadataRead) {
		findings = append(findings, ExposureClassification{
			ID:             idPublicAdminRead,
			Resource:       c.input.Name,
			ExposureType:   TypePublicMetaRead,
			PrincipalScope: scope,
			Actions:        []string{ActionAdminRead},
			EvidencePath:   c.evidence.Get(EvResourceAdminRead),
		})
	}
	if perms.Has(PermMetadataWrite) {
		findings = append(findings, ExposureClassification{
			ID:             idPublicAdminWrite,
			Resource:       c.input.Name,
			ExposureType:   TypePublicMetaWrite,
			PrincipalScope: scope,
			Actions:        []string{ActionAdminWrite},
			EvidencePath:   c.evidence.Get(EvResourceAdminRead),
		})
	}
	if perms.Has(PermDelete) {
		findings = append(findings, ExposureClassification{
			ID:             idPublicDelete,
			Resource:       c.input.Name,
			ExposureType:   TypePublicDelete,
			PrincipalScope: scope,
			Actions:        []string{ActionDelete},
			EvidencePath:   c.evidence.Get(EvDelete),
		})
	}
	return findings
}
