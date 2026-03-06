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

func (c *bucketResolutionContext) recordPolicyPermissions(perms statementPermission, evidence []string) {
	c.recordPermissions(permissionInspectionRequest{
		Perms:         perms,
		EvidencePath:  evidence,
		Set:           &c.policyPerms,
		ReadEvidence:  evidencePolicyRead,
		WriteEvidence: evidencePolicyWrite,
	})
}

func analyzeStatementActions(actions []string) statementPermission {
	var total statementPermission
	for _, action := range actions {
		a := strings.ToLower(action)
		if p, ok := actionToPermission[a]; ok {
			total |= p
		}
		if total == stmtPermAll {
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
		c.recordACLPermissions(statementPermission(grant.ExposurePermissions()), aclEvidence(i))
	}
}

func (c *bucketResolutionContext) recordACLPermissions(perms statementPermission, evidence []string) {
	c.recordPermissions(permissionInspectionRequest{
		Perms:         perms,
		EvidencePath:  evidence,
		Set:           &c.aclPerms,
		ReadEvidence:  evidenceACLRead,
		WriteEvidence: evidenceACLWrite,
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
	Perms        statementPermission
	Bit          statementPermission
	Target       *bool
	EvidenceKey  string
	EvidencePath []string
	Tracker      *evidenceTracker
}

func recordIf(req permissionRecordRequest) {
	if !req.Perms.has(req.Bit) {
		return
	}
	*req.Target = true
	req.Tracker.Record(req.EvidenceKey, req.EvidencePath)
}

type permissionInspectionRequest struct {
	Perms         statementPermission
	EvidencePath  []string
	Set           *permissionSet
	ReadEvidence  string
	WriteEvidence string
}

func (c *bucketResolutionContext) recordPermissions(req permissionInspectionRequest) {
	if req.Set == nil {
		return
	}

	recordIf(permissionRecordRequest{
		Perms:        req.Perms,
		Bit:          stmtPermRead,
		Target:       &req.Set.Get,
		EvidenceKey:  req.ReadEvidence,
		EvidencePath: req.EvidencePath,
		Tracker:      &c.evidence,
	})
	recordIf(permissionRecordRequest{
		Perms:        req.Perms,
		Bit:          stmtPermList,
		Target:       &req.Set.List,
		EvidenceKey:  evidenceList,
		EvidencePath: req.EvidencePath,
		Tracker:      &c.evidence,
	})
	recordIf(permissionRecordRequest{
		Perms:        req.Perms,
		Bit:          stmtPermACLRead,
		Target:       &req.Set.ACLRead,
		EvidenceKey:  evidenceACLReadPolicy,
		EvidencePath: req.EvidencePath,
		Tracker:      &c.evidence,
	})
	recordIf(permissionRecordRequest{
		Perms:        req.Perms,
		Bit:          stmtPermACLWrite,
		Target:       &req.Set.ACLWrite,
		EvidenceKey:  evidenceACLWritePolicy,
		EvidencePath: req.EvidencePath,
		Tracker:      &c.evidence,
	})
	recordIf(permissionRecordRequest{
		Perms:        req.Perms,
		Bit:          stmtPermDelete,
		Target:       &req.Set.Delete,
		EvidenceKey:  evidenceDelete,
		EvidencePath: req.EvidencePath,
		Tracker:      &c.evidence,
	})

	if req.Perms.has(stmtPermWrite) {
		if !req.Set.Put {
			c.writeSource.HasGet = req.Perms.has(stmtPermRead)
			c.writeSource.HasList = req.Perms.has(stmtPermList)
		}
		req.Set.Put = true
		c.evidence.Record(req.WriteEvidence, req.EvidencePath)
	}
}
