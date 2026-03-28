package asset

const (
	pathPolicyStatements = "source_evidence.policy_public_statements"
	pathACLGrantees      = "source_evidence.acl_public_grantees"
)

// PolicyStatementIDs returns the identity-bound policy statement IDs
// from the source_evidence property namespace.
func (a Asset) PolicyStatementIDs() []string {
	return a.Metadata().GetPath(pathPolicyStatements).StringSlice()
}

// ACLGranteeIDs returns the resource-bound ACL grantee URIs
// from the source_evidence property namespace.
func (a Asset) ACLGranteeIDs() []string {
	return a.Metadata().GetPath(pathACLGrantees).StringSlice()
}
