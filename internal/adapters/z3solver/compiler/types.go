//go:build cgo && z3

package compiler

// Types duplicated from pkg/stave to break the import cycle.
// The prove facade converts between these and the public types.

type Exports struct {
	Policies   *PolicyExport
	Graph      *GraphExport
	Invariants *InvariantExport
}

type PolicyExport struct {
	ResourcePolicies   []PolicyDocument
	TrustPolicies      []TrustDocument
	KMSKeyPolicies     []PolicyDocument
	AssetRelationships []AssetEdge
}

type PolicyDocument struct {
	SourceAssetID string
	PolicyType    string
	Statements    []PolicyStatement
}

type TrustDocument struct {
	SourceAssetID string
	Statements    []PolicyStatement
}

type PolicyStatement struct {
	Sid           string
	Effect        string
	Principals    []string
	NotPrincipals []string
	Actions       []string
	NotActions    []string
	Resources     []string
	NotResources  []string
	Conditions    []Condition
}

type Condition struct {
	Operator string
	Key      string
	Values   []string
}

type AssetEdge struct {
	FromAssetID  string
	ToAssetID    string
	Relationship string
}

type GraphExport struct {
	Assets []AssetNode
}

type AssetNode struct {
	ID   string
	Type string
}

type InvariantExport struct {
	Invariants []InvariantDefinition
}

type InvariantDefinition struct {
	ID        string
	Severity  string
	Predicate PredicateExport
}

type PredicateExport struct {
	Combine  string
	Children []PredicateExport
	Property string
	Operator string
	Expected any
}

func (p PredicateExport) IsLeaf() bool {
	return p.Combine == ""
}
