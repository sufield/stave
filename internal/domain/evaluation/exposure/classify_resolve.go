package exposure

import "github.com/sufield/stave/internal/domain/kernel"

func newBucketResolutionContext(input ExposureBucketInput) bucketResolutionContext {
	ctx := bucketResolutionContext{
		input:                input,
		hasAuthenticatedOnly: true,
		evidence:             newEvidenceTracker(),
	}
	ctx.inspectPolicy()
	ctx.inspectACL()
	return ctx
}

func (c *bucketResolutionContext) globalPerms() permissionSet {
	return c.policyPerms.merged(c.aclPerms)
}

func (c *bucketResolutionContext) principalScope() kernel.PrincipalScope {
	if c.hasAuthenticatedOnly {
		return kernel.ScopeAuthenticated
	}
	return kernel.ScopePublic
}

func (c *bucketResolutionContext) readEvidence() []string {
	if ev := c.evidence.Get(evidencePolicyRead); len(ev) > 0 {
		return ev
	}
	return c.evidence.Get(evidenceACLRead)
}

func (c *bucketResolutionContext) writeScope() string {
	perms := c.globalPerms()
	if !perms.Put {
		return ""
	}
	if perms.Get || perms.List {
		return "full"
	}
	return "blind"
}

func (c *bucketResolutionContext) writeAbsorbsRead() bool {
	perms := c.globalPerms()
	return perms.Put && c.policyPerms.Put && c.writeSource.HasGet
}

func (c *bucketResolutionContext) resolveRead() []ExposureClassification {
	perms := c.globalPerms()
	selected := selectReadExposureCandidate(readExposureInput{
		bucketName:           c.input.Name,
		bucketWebsiteEnabled: c.input.Website.Enabled,
		globalGet:            perms.Get,
		writeAbsorbsRead:     c.writeAbsorbsRead(),
		hasAuthenticatedOnly: c.hasAuthenticatedOnly,
		policyGet:            c.policyPerms.Get,
		aclGet:               c.aclPerms.Get,
		principalScope:       c.principalScope(),
		readEvidence:         c.readEvidence(),
		policyReadEvidence:   c.evidence.Get(evidencePolicyRead),
		aclReadEvidence:      c.evidence.Get(evidenceACLRead),
	})
	if selected == nil {
		return nil
	}
	return []ExposureClassification{selected.finding}
}

func (c *bucketResolutionContext) resolveList() []ExposureClassification {
	perms := c.globalPerms()
	if !perms.List {
		return nil
	}
	return []ExposureClassification{{
		ID:             exposureIDPublicList,
		Bucket:         c.input.Name,
		ExposureType:   "public_list",
		PrincipalScope: c.principalScope(),
		Actions:        []string{outputListBucket},
		EvidencePath:   c.evidence.Get(evidenceList),
	}}
}

func (c *bucketResolutionContext) resolveWrite() []ExposureClassification {
	perms := c.globalPerms()
	selected := selectWriteExposureCandidate(writeExposureInput{
		bucketName:          c.input.Name,
		globalPut:           perms.Put,
		policyPut:           c.policyPerms.Put,
		aclPut:              c.aclPerms.Put,
		principalScope:      c.principalScope(),
		writeScope:          c.writeScope(),
		policyWriteEvidence: c.evidence.Get(evidencePolicyWrite),
		aclWriteEvidence:    c.evidence.Get(evidenceACLWrite),
		writeSourceHasGet:   c.writeSource.HasGet,
		writeSourceHasList:  c.writeSource.HasList,
	})
	if selected == nil {
		return nil
	}
	return []ExposureClassification{selected.finding}
}

func (c *bucketResolutionContext) resolveManagement() []ExposureClassification {
	perms := c.globalPerms()
	findings := make([]ExposureClassification, 0, 3)
	if perms.ACLRead {
		findings = append(findings, ExposureClassification{
			ID:             exposureIDPublicACLRead,
			Bucket:         c.input.Name,
			ExposureType:   "public_acl_read",
			PrincipalScope: c.principalScope(),
			Actions:        []string{outputGetBucketACL},
			EvidencePath:   c.evidence.Get(evidenceACLReadPolicy),
		})
	}
	if perms.ACLWrite {
		findings = append(findings, ExposureClassification{
			ID:             exposureIDPublicACLWrite,
			Bucket:         c.input.Name,
			ExposureType:   "public_acl_write",
			PrincipalScope: c.principalScope(),
			Actions:        []string{outputPutBucketACL},
			EvidencePath:   c.evidence.Get(evidenceACLWritePolicy),
		})
	}
	if perms.Delete {
		findings = append(findings, ExposureClassification{
			ID:             exposureIDPublicDelete,
			Bucket:         c.input.Name,
			ExposureType:   "public_delete",
			PrincipalScope: c.principalScope(),
			Actions:        []string{outputDeleteObject},
			EvidencePath:   c.evidence.Get(evidenceDelete),
		})
	}
	return findings
}
