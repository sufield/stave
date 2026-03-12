package exposure

import "github.com/sufield/stave/internal/domain/kernel"

func (c *bucketResolutionContext) globalPerms() Permission {
	return c.input.PolicyPerms | c.input.ACLPerms
}

func (c *bucketResolutionContext) principalScope() kernel.PrincipalScope {
	if c.input.IsAuthenticatedOnly {
		return kernel.ScopeAuthenticated
	}
	return kernel.ScopePublic
}

func (c *bucketResolutionContext) readEvidence() []string {
	if ev := c.input.Evidence.Get(EvPolicyRead); len(ev) > 0 {
		return ev
	}
	return c.input.Evidence.Get(EvACLRead)
}

func (c *bucketResolutionContext) writeScope() string {
	perms := c.globalPerms()
	if !perms.Has(PermWrite) {
		return ""
	}
	if perms.Has(PermRead) || perms.Has(PermList) {
		return "full"
	}
	return "blind"
}

func (c *bucketResolutionContext) writeAbsorbsRead() bool {
	perms := c.globalPerms()
	return perms.Has(PermWrite) && c.input.PolicyPerms.Has(PermWrite) && c.input.WriteSourceHasGet
}

func (c *bucketResolutionContext) resolveRead() []ExposureClassification {
	perms := c.globalPerms()
	selected := SelectReadExposure(ReadExposureInput{
		ResourceID:           c.input.Name,
		WebHostingEnabled:    c.input.WebsiteEnabled,
		IsExternallyReadable: perms.Has(PermRead),
		WriteAbsorbsRead:     c.writeAbsorbsRead(),
		IsAuthenticatedOnly:  c.input.IsAuthenticatedOnly,
		HasIdentityRead:      c.input.PolicyPerms.Has(PermRead),
		HasResourceRead:      c.input.ACLPerms.Has(PermRead),
		PrincipalScope:       c.principalScope(),
		EvidenceGeneral:      c.readEvidence(),
		EvidenceIdentity:     c.input.Evidence.Get(EvPolicyRead),
		EvidenceResource:     c.input.Evidence.Get(EvACLRead),
		Actions:              []string{"Read"},
	})
	if selected == nil {
		return nil
	}
	return []ExposureClassification{selected.finding}
}

func (c *bucketResolutionContext) resolveList() []ExposureClassification {
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
		EvidencePath:   c.input.Evidence.Get(EvList),
	}}
}

func (c *bucketResolutionContext) resolveWrite() []ExposureClassification {
	perms := c.globalPerms()
	selected := SelectWriteExposure(WriteExposureInput{
		ResourceID:       c.input.Name,
		IsPubliclyWrite:  perms.Has(PermWrite),
		HasIdentityWrite: c.input.PolicyPerms.Has(PermWrite),
		HasResourceWrite: c.input.ACLPerms.Has(PermWrite),
		PrincipalScope:   c.principalScope(),
		WriteScope:       c.writeScope(),
		EvidenceIdentity: c.input.Evidence.Get(EvPolicyWrite),
		EvidenceResource: c.input.Evidence.Get(EvACLWrite),
		CanAlsoRead:      c.input.WriteSourceHasGet,
		CanAlsoList:      c.input.WriteSourceHasList,
		BaseActions:      []string{"Write"},
	})
	if selected == nil {
		return nil
	}
	return []ExposureClassification{selected.finding}
}

func (c *bucketResolutionContext) resolveManagement() []ExposureClassification {
	perms := c.globalPerms()
	findings := make([]ExposureClassification, 0, 3)
	if perms.Has(PermACLRead) {
		findings = append(findings, ExposureClassification{
			ID:             idPublicAdminRead,
			Resource:       c.input.Name,
			ExposureType:   "public_acl_read",
			PrincipalScope: c.principalScope(),
			Actions:        []string{outputGetBucketACL},
			EvidencePath:   c.input.Evidence.Get(EvACLReadPolicy),
		})
	}
	if perms.Has(PermACLWrite) {
		findings = append(findings, ExposureClassification{
			ID:             idPublicAdminWrite,
			Resource:       c.input.Name,
			ExposureType:   "public_acl_write",
			PrincipalScope: c.principalScope(),
			Actions:        []string{outputPutBucketACL},
			EvidencePath:   c.input.Evidence.Get(EvACLWritePolicy),
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
