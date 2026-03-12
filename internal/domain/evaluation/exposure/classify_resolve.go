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
	selected := selectReadExposureCandidate(readExposureInput{
		bucketName:           c.input.Name,
		bucketWebsiteEnabled: c.input.WebsiteEnabled,
		isGlobalGet:          perms.Has(PermRead),
		writeAbsorbsRead:     c.writeAbsorbsRead(),
		isAuthenticatedOnly:  c.input.IsAuthenticatedOnly,
		isPolicyGet:          c.input.PolicyPerms.Has(PermRead),
		isACLGet:             c.input.ACLPerms.Has(PermRead),
		principalScope:       c.principalScope(),
		readEvidence:         c.readEvidence(),
		policyReadEvidence:   c.input.Evidence.Get(EvPolicyRead),
		aclReadEvidence:      c.input.Evidence.Get(EvACLRead),
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
		ID:             exposureIDPublicList,
		Bucket:         c.input.Name,
		ExposureType:   "public_list",
		PrincipalScope: c.principalScope(),
		Actions:        []string{outputListBucket},
		EvidencePath:   c.input.Evidence.Get(EvList),
	}}
}

func (c *bucketResolutionContext) resolveWrite() []ExposureClassification {
	perms := c.globalPerms()
	selected := selectWriteExposureCandidate(writeExposureInput{
		bucketName:          c.input.Name,
		isGlobalPut:         perms.Has(PermWrite),
		isPolicyPut:         c.input.PolicyPerms.Has(PermWrite),
		isACLPut:            c.input.ACLPerms.Has(PermWrite),
		principalScope:      c.principalScope(),
		writeScope:          c.writeScope(),
		policyWriteEvidence: c.input.Evidence.Get(EvPolicyWrite),
		aclWriteEvidence:    c.input.Evidence.Get(EvACLWrite),
		hasGetAction:        c.input.WriteSourceHasGet,
		hasListAction:       c.input.WriteSourceHasList,
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
			ID:             exposureIDPublicACLRead,
			Bucket:         c.input.Name,
			ExposureType:   "public_acl_read",
			PrincipalScope: c.principalScope(),
			Actions:        []string{outputGetBucketACL},
			EvidencePath:   c.input.Evidence.Get(EvACLReadPolicy),
		})
	}
	if perms.Has(PermACLWrite) {
		findings = append(findings, ExposureClassification{
			ID:             exposureIDPublicACLWrite,
			Bucket:         c.input.Name,
			ExposureType:   "public_acl_write",
			PrincipalScope: c.principalScope(),
			Actions:        []string{outputPutBucketACL},
			EvidencePath:   c.input.Evidence.Get(EvACLWritePolicy),
		})
	}
	if perms.Has(PermDelete) {
		findings = append(findings, ExposureClassification{
			ID:             exposureIDPublicDelete,
			Bucket:         c.input.Name,
			ExposureType:   "public_delete",
			PrincipalScope: c.principalScope(),
			Actions:        []string{outputDeleteObject},
			EvidencePath:   c.input.Evidence.Get(EvDelete),
		})
	}
	return findings
}
