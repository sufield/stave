package exposure

import (
	"fmt"
	"strings"
)

func (c *bucketResolutionContext) inspectPolicy() {
	for i, stmt := range c.input.Policy.Statements {
		if strings.ToLower(stmt.Effect) != "allow" {
			continue
		}

		isGlobal, isAuthenticated := classifyPrincipal(stmt.Principal)
		if !isGlobal && !isAuthenticated {
			continue
		}
		if isGlobal {
			c.hasAuthenticatedOnly = false
		}

		perms := analyzeStatementActions(stmt.Actions)
		c.recordPolicyPermissions(perms, policyEvidence(i))
	}
}

func (c *bucketResolutionContext) recordPolicyPermissions(perms Permission, evidence []string) {
	c.recordPermissions(permissionInspectionRequest{
		Perms:         perms,
		EvidencePath:  evidence,
		Set:           &c.policyPerms,
		ReadEvidence:  EvPolicyRead,
		WriteEvidence: EvPolicyWrite,
	})
}

func analyzeStatementActions(actions []string) Permission {
	var total Permission
	for _, action := range actions {
		a := strings.ToLower(action)
		if p, ok := actionToPerm[a]; ok {
			total |= p
		}
		if total == PermAll {
			break
		}
	}
	return total
}

func policyEvidence(stmtIdx int) []string {
	return []string{
		fmt.Sprintf("bucket.policy.statements[%d].effect", stmtIdx),
		fmt.Sprintf("bucket.policy.statements[%d].principal", stmtIdx),
		fmt.Sprintf("bucket.policy.statements[%d].actions", stmtIdx),
	}
}

func (c *bucketResolutionContext) inspectACL() {
	for i, grant := range c.input.ACL.Grants {
		if !grant.IsPublic() {
			continue
		}
		if grant.IsAllUsers() {
			c.hasAuthenticatedOnly = false
		}
		c.recordACLPermissions(grant.ExposurePermissions(), aclEvidence(i))
	}
}

func (c *bucketResolutionContext) recordACLPermissions(perms Permission, evidence []string) {
	c.recordPermissions(permissionInspectionRequest{
		Perms:         perms,
		EvidencePath:  evidence,
		Set:           &c.aclPerms,
		ReadEvidence:  EvACLRead,
		WriteEvidence: EvACLWrite,
	})
}

func aclEvidence(grantIdx int) []string {
	return []string{
		fmt.Sprintf("bucket.acl.grants[%d].grantee", grantIdx),
		fmt.Sprintf("bucket.acl.grants[%d].permission", grantIdx),
		fmt.Sprintf("bucket.acl.grants[%d].scope", grantIdx),
	}
}

type permissionRecordRequest struct {
	Perms        Permission
	Bit          Permission
	Target       *bool
	EvidenceKey  EvidenceCategory
	EvidencePath []string
	Tracker      *EvidenceTracker
}

func recordIf(req permissionRecordRequest) {
	if !req.Perms.Has(req.Bit) {
		return
	}
	*req.Target = true
	req.Tracker.Record(req.EvidenceKey, req.EvidencePath)
}

type permissionInspectionRequest struct {
	Perms         Permission
	EvidencePath  []string
	Set           *permissionSet
	ReadEvidence  EvidenceCategory
	WriteEvidence EvidenceCategory
}

func (c *bucketResolutionContext) recordPermissions(req permissionInspectionRequest) {
	if req.Set == nil {
		return
	}

	recordIf(permissionRecordRequest{
		Perms:        req.Perms,
		Bit:          PermRead,
		Target:       &req.Set.Get,
		EvidenceKey:  req.ReadEvidence,
		EvidencePath: req.EvidencePath,
		Tracker:      c.evidence,
	})
	recordIf(permissionRecordRequest{
		Perms:        req.Perms,
		Bit:          PermList,
		Target:       &req.Set.List,
		EvidenceKey:  EvList,
		EvidencePath: req.EvidencePath,
		Tracker:      c.evidence,
	})
	recordIf(permissionRecordRequest{
		Perms:        req.Perms,
		Bit:          PermACLRead,
		Target:       &req.Set.ACLRead,
		EvidenceKey:  EvACLReadPolicy,
		EvidencePath: req.EvidencePath,
		Tracker:      c.evidence,
	})
	recordIf(permissionRecordRequest{
		Perms:        req.Perms,
		Bit:          PermACLWrite,
		Target:       &req.Set.ACLWrite,
		EvidenceKey:  EvACLWritePolicy,
		EvidencePath: req.EvidencePath,
		Tracker:      c.evidence,
	})
	recordIf(permissionRecordRequest{
		Perms:        req.Perms,
		Bit:          PermDelete,
		Target:       &req.Set.Delete,
		EvidenceKey:  EvDelete,
		EvidencePath: req.EvidencePath,
		Tracker:      c.evidence,
	})

	if req.Perms.Has(PermWrite) {
		if !req.Set.Put {
			c.writeSource.HasGet = req.Perms.Has(PermRead)
			c.writeSource.HasList = req.Perms.Has(PermList)
		}
		req.Set.Put = true
		c.evidence.Record(req.WriteEvidence, req.EvidencePath)
	}
}
