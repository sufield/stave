package exposure

import "github.com/sufield/stave/internal/domain/kernel"

func (c *resolutionContext) globalPerms() Permission {
	return c.input.IdentityPerms | c.input.ResourcePerms
}

func (c *resolutionContext) principalScope() kernel.PrincipalScope {
	if c.input.IsAuthenticatedOnly {
		return kernel.ScopeAuthenticated
	}
	return kernel.ScopePublic
}

func (c *resolutionContext) readEvidence() []string {
	if ev := c.input.Evidence.Get(EvIdentityRead); len(ev) > 0 {
		return ev
	}
	return c.input.Evidence.Get(EvResourceRead)
}

func (c *resolutionContext) writeScope() string {
	perms := c.globalPerms()
	if !perms.Has(PermWrite) {
		return ""
	}
	if perms.Has(PermRead) || perms.Has(PermList) {
		return "full"
	}
	return "blind"
}

func (c *resolutionContext) writeAbsorbsRead() bool {
	perms := c.globalPerms()
	return perms.Has(PermWrite) && c.input.IdentityPerms.Has(PermWrite) && c.input.WriteSourceHasGet
}

func (c *resolutionContext) resolveRead() []ExposureClassification {
	perms := c.globalPerms()
	selected := SelectReadExposure(ReadExposureInput{
		ResourceID:           c.input.Name,
		WebHostingEnabled:    c.input.WebsiteEnabled,
		IsExternallyReadable: perms.Has(PermRead),
		WriteAbsorbsRead:     c.writeAbsorbsRead(),
		IsAuthenticatedOnly:  c.input.IsAuthenticatedOnly,
		HasIdentityRead:      c.input.IdentityPerms.Has(PermRead),
		HasResourceRead:      c.input.ResourcePerms.Has(PermRead),
		PrincipalScope:       c.principalScope(),
		EvidenceGeneral:      c.readEvidence(),
		EvidenceIdentity:     c.input.Evidence.Get(EvIdentityRead),
		EvidenceResource:     c.input.Evidence.Get(EvResourceRead),
		Actions:              []string{"Read"},
	})
	if selected == nil {
		return nil
	}
	return []ExposureClassification{selected.finding}
}

func (c *resolutionContext) resolveList() []ExposureClassification {
	perms := c.globalPerms()
	if !perms.Has(PermList) {
		return nil
	}
	return []ExposureClassification{{
		ID:             idPublicList,
		Resource:       c.input.Name,
		ExposureType:   "public_list",
		PrincipalScope: c.principalScope(),
		Actions:        []string{outputListBucket},
		EvidencePath:   c.input.Evidence.Get(EvDiscovery),
	}}
}

func (c *resolutionContext) resolveWrite() []ExposureClassification {
	perms := c.globalPerms()
	selected := SelectWriteExposure(WriteExposureInput{
		ResourceID:       c.input.Name,
		IsPubliclyWrite:  perms.Has(PermWrite),
		HasIdentityWrite: c.input.IdentityPerms.Has(PermWrite),
		HasResourceWrite: c.input.ResourcePerms.Has(PermWrite),
		PrincipalScope:   c.principalScope(),
		WriteScope:       c.writeScope(),
		EvidenceIdentity: c.input.Evidence.Get(EvIdentityWrite),
		EvidenceResource: c.input.Evidence.Get(EvResourceWrite),
		CanAlsoRead:      c.input.WriteSourceHasGet,
		CanAlsoList:      c.input.WriteSourceHasList,
		BaseActions:      []string{"Write"},
	})
	if selected == nil {
		return nil
	}
	return []ExposureClassification{selected.finding}
}

func (c *resolutionContext) resolveManagement() []ExposureClassification {
	perms := c.globalPerms()
	findings := make([]ExposureClassification, 0, 3)
	if perms.Has(PermMetadataRead) {
		findings = append(findings, ExposureClassification{
			ID:             idPublicAdminRead,
			Resource:       c.input.Name,
			ExposureType:   "public_acl_read",
			PrincipalScope: c.principalScope(),
			Actions:        []string{outputGetBucketACL},
			EvidencePath:   c.input.Evidence.Get(EvMetadataRead),
		})
	}
	if perms.Has(PermMetadataWrite) {
		findings = append(findings, ExposureClassification{
			ID:             idPublicAdminWrite,
			Resource:       c.input.Name,
			ExposureType:   "public_acl_write",
			PrincipalScope: c.principalScope(),
			Actions:        []string{outputPutBucketACL},
			EvidencePath:   c.input.Evidence.Get(EvMetadataWrite),
		})
	}
	if perms.Has(PermDelete) {
		findings = append(findings, ExposureClassification{
			ID:             idPublicDelete,
			Resource:       c.input.Name,
			ExposureType:   "public_delete",
			PrincipalScope: c.principalScope(),
			Actions:        []string{outputDeleteObject},
			EvidencePath:   c.input.Evidence.Get(EvDelete),
		})
	}
	return findings
}
