// Package policyexport extracts structured policy documents and
// asset relationships from observation snapshots. The output is
// designed for external solver consumption (Z3, Neo4j, custom
// reasoners) and carries no engine-side semantics — it is a pure
// projection of the observation data into typed Go values.
//
// Internal to pkg/stave; the public surface lives in
// pkg/stave/export.go and re-exports the types defined here through
// thin wrappers.
package policyexport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/util/props"
)

// Config configures snapshot loading for the export.
type Config struct {
	SnapshotsDir      string
	AllowUnknownInput bool
}

// Result is the structured policy data extracted from one or more
// snapshots. Per-asset duplicates are kept — a single asset can
// have a resource policy, a key policy, and act as the source of
// an asset edge, so consumers see every shape independently.
type Result struct {
	GeneratedAt        time.Time
	ResourcePolicies   []PolicyDocument
	TrustPolicies      []TrustDocument
	KMSKeyPolicies     []PolicyDocument
	AssetRelationships []AssetEdge
}

// PolicyDocument is a parsed AWS-style policy document keyed to
// the asset that owns it. PolicyType disambiguates which
// observation field the document came from so the consumer can
// differentiate (e.g.) a resource policy from a KMS key policy
// even when both surface as PolicyDocument.
type PolicyDocument struct {
	SourceAssetID string
	PolicyType    string
	Statements    []PolicyStatement
}

// TrustDocument is an IAM role trust policy. Distinct from
// PolicyDocument so consumers can branch on the document kind
// without inspecting PolicyType.
type TrustDocument struct {
	SourceAssetID string
	Statements    []PolicyStatement
}

// PolicyStatement carries the structured statement shape every
// AWS-style policy follows. NotPrincipals / NotActions /
// NotResources are surfaced separately so consumers can encode the
// negative-form semantics directly without re-parsing the raw JSON.
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

// Condition carries a single AWS policy condition row. Each row
// pairs an operator (e.g. "StringEquals", "ArnLike", "Bool") with
// a key (e.g. "aws:PrincipalOrgID") and one or more expected
// values. The wire format collapses condition entries with the same
// operator+key into a single map; we expand to one Condition per
// (operator, key) pair so consumers can iterate without re-walking
// the nested map.
type Condition struct {
	Operator string
	Key      string
	Values   []string
}

// AssetEdge records a relationship between two assets observable
// in the snapshot. The edge is directional; Relationship names the
// shape of the link (e.g. "encrypts_with" for a bucket pointing at
// its KMS key). External tools (Neo4j, Z3) consume the edge list
// to compute reachability without re-walking the property bags.
type AssetEdge struct {
	FromAssetID  string
	ToAssetID    string
	Relationship string
}

// resourcePolicyTarget pairs a property path with the policy-type
// label emitted on the resulting PolicyDocument. Mirrors the
// canonical resource-policy paths the IAM provider already
// enumerates (internal/platform/providers/aws/iam/index_builder.go)
// — kept here as a literal so the export does not depend on a
// provider-internal slice.
type resourcePolicyTarget struct {
	path  []string
	label string
}

var resourcePolicyTargets = []resourcePolicyTarget{
	{[]string{"storage", "policy_json"}, "s3_bucket"},
	{[]string{"compute", "resource_policy_json"}, "lambda"},
	{[]string{"messaging", "policy_json"}, "messaging"},
	{[]string{"secret", "resource_policy_json"}, "secret"},
}

// kmsKeyPolicyPath is the canonical path for a KMS key policy.
// Surfaced separately so KMSKeyPolicies stays distinct from the
// generic ResourcePolicies bucket.
var kmsKeyPolicyPath = []string{"encryption", "key_policy_json"}

// kmsKeyArnPath / kmsKeyIDPath are the canonical paths the
// extractor consults to derive a (resource → KMS key) edge from
// the encryption block. Both forms appear in real observations:
// the ARN form when the producer captured a fully-qualified
// reference, the ID form for KMS-managed defaults.
var (
	kmsKeyArnPath = []string{"encryption", "key_arn"}
	kmsKeyIDPath  = []string{"encryption", "key_id"}
)

// Run loads the snapshots from cfg.SnapshotsDir and walks every
// asset and identity to build the export. Latest snapshot wins on
// duplicate (asset_id, policy_type) tuples — the export is a
// point-in-time projection, not an append-only log.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.SnapshotsDir == "" {
		return nil, errors.New("policyexport: SnapshotsDir is required")
	}

	loader := observations.NewObservationLoader()
	loaded, err := loader.LoadSnapshots(ctx, cfg.SnapshotsDir)
	if err != nil {
		return nil, fmt.Errorf("policyexport: load snapshots: %w", err)
	}

	r := newResultBuilder()
	for i := range loaded.Snapshots {
		snap := &loaded.Snapshots[i]
		if r.latestAt.IsZero() || snap.CapturedAt.After(r.latestAt) {
			r.latestAt = snap.CapturedAt
		}
		for j := range snap.Assets {
			r.processAsset(&snap.Assets[j])
		}
		for j := range snap.Identities {
			r.processIdentity(&snap.Identities[j])
		}
	}
	return r.finalize(), nil
}

type resultBuilder struct {
	latestAt time.Time

	resourcePolicies map[string]PolicyDocument
	trustPolicies    map[string]TrustDocument
	kmsKeyPolicies   map[string]PolicyDocument
	edges            map[string]AssetEdge
}

func newResultBuilder() *resultBuilder {
	return &resultBuilder{
		resourcePolicies: map[string]PolicyDocument{},
		trustPolicies:    map[string]TrustDocument{},
		kmsKeyPolicies:   map[string]PolicyDocument{},
		edges:            map[string]AssetEdge{},
	}
}

func (r *resultBuilder) processAsset(a *asset.Asset) {
	if a.Properties == nil {
		return
	}
	id := string(a.ID)

	for _, target := range resourcePolicyTargets {
		raw := props.GetString(a.Properties, target.path)
		if raw == "" {
			continue
		}
		stmts, err := parseStatements(raw)
		if err != nil {
			continue
		}
		key := id + "|" + target.label
		r.resourcePolicies[key] = PolicyDocument{
			SourceAssetID: id,
			PolicyType:    target.label,
			Statements:    stmts,
		}
	}

	if raw := props.GetString(a.Properties, kmsKeyPolicyPath); raw != "" {
		if stmts, err := parseStatements(raw); err == nil {
			r.kmsKeyPolicies[id] = PolicyDocument{
				SourceAssetID: id,
				PolicyType:    "kms_key",
				Statements:    stmts,
			}
		}
	}

	if keyRef := firstNonEmpty(
		props.GetString(a.Properties, kmsKeyArnPath),
		props.GetString(a.Properties, kmsKeyIDPath),
	); keyRef != "" {
		r.recordEdge(AssetEdge{
			FromAssetID:  id,
			ToAssetID:    keyRef,
			Relationship: "encrypts_with",
		})
	}
}

func (r *resultBuilder) processIdentity(idn *asset.CloudIdentity) {
	if idn.Properties == nil {
		return
	}
	id := string(idn.ID)

	if raw := props.GetString(idn.Properties, []string{"identity", "trust_policy_json"}); raw != "" {
		if stmts, err := parseStatements(raw); err == nil {
			r.trustPolicies[id] = TrustDocument{
				SourceAssetID: id,
				Statements:    stmts,
			}
			for _, principal := range distinctPrincipals(stmts) {
				r.recordEdge(AssetEdge{
					FromAssetID:  principal,
					ToAssetID:    id,
					Relationship: "assumes",
				})
			}
		}
	}
}

func (r *resultBuilder) recordEdge(e AssetEdge) {
	key := e.FromAssetID + "|" + e.Relationship + "|" + e.ToAssetID
	r.edges[key] = e
}

func (r *resultBuilder) finalize() *Result {
	return &Result{
		GeneratedAt:        r.latestAt,
		ResourcePolicies:   sortedDocs(r.resourcePolicies),
		KMSKeyPolicies:     sortedDocs(r.kmsKeyPolicies),
		TrustPolicies:      sortedTrustDocs(r.trustPolicies),
		AssetRelationships: sortedEdges(r.edges),
	}
}

func sortedDocs(m map[string]PolicyDocument) []PolicyDocument {
	if len(m) == 0 {
		return nil
	}
	out := make([]PolicyDocument, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceAssetID != out[j].SourceAssetID {
			return out[i].SourceAssetID < out[j].SourceAssetID
		}
		return out[i].PolicyType < out[j].PolicyType
	})
	return out
}

func sortedTrustDocs(m map[string]TrustDocument) []TrustDocument {
	if len(m) == 0 {
		return nil
	}
	out := make([]TrustDocument, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SourceAssetID < out[j].SourceAssetID
	})
	return out
}

func sortedEdges(m map[string]AssetEdge) []AssetEdge {
	if len(m) == 0 {
		return nil
	}
	out := make([]AssetEdge, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FromAssetID != out[j].FromAssetID {
			return out[i].FromAssetID < out[j].FromAssetID
		}
		if out[i].Relationship != out[j].Relationship {
			return out[i].Relationship < out[j].Relationship
		}
		return out[i].ToAssetID < out[j].ToAssetID
	})
	return out
}

// parseStatements decodes a raw AWS-style policy JSON into the
// export's PolicyStatement form. Empty / whitespace input returns
// (nil, nil) — callers treat that as "no policy attached" and skip
// the entry, matching iam.ParsePolicyDocument's contract.
func parseStatements(raw string) ([]PolicyStatement, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if len(doc.Statement) == 0 || string(doc.Statement) == "null" {
		return nil, nil
	}

	// Statement is either a single object or an array of objects.
	var stmts []json.RawMessage
	if err := json.Unmarshal(doc.Statement, &stmts); err != nil {
		var single json.RawMessage
		if err2 := json.Unmarshal(doc.Statement, &single); err2 != nil {
			return nil, fmt.Errorf("parse Statement: %w", err)
		}
		stmts = []json.RawMessage{single}
	}

	out := make([]PolicyStatement, 0, len(stmts))
	for i := range stmts {
		var s rawStatement
		if err := json.Unmarshal(stmts[i], &s); err != nil {
			return nil, fmt.Errorf("parse statement %d: %w", i, err)
		}
		out = append(out, s.toExport())
	}
	return out, nil
}

// rawStatement mirrors the AWS policy-statement wire shape with
// json.RawMessage on the polymorphic fields. Each accessor below
// normalises the string-or-array shapes AWS accepts.
type rawStatement struct {
	Sid          string          `json:"Sid"`
	Effect       string          `json:"Effect"`
	Principal    json.RawMessage `json:"Principal"`
	NotPrincipal json.RawMessage `json:"NotPrincipal"`
	Action       json.RawMessage `json:"Action"`
	NotAction    json.RawMessage `json:"NotAction"`
	Resource     json.RawMessage `json:"Resource"`
	NotResource  json.RawMessage `json:"NotResource"`
	Condition    json.RawMessage `json:"Condition"`
}

func (s rawStatement) toExport() PolicyStatement {
	return PolicyStatement{
		Sid:           s.Sid,
		Effect:        s.Effect,
		Principals:    flattenPrincipals(s.Principal),
		NotPrincipals: flattenPrincipals(s.NotPrincipal),
		Actions:       stringOrList(s.Action),
		NotActions:    stringOrList(s.NotAction),
		Resources:     stringOrList(s.Resource),
		NotResources:  stringOrList(s.NotResource),
		Conditions:    flattenConditions(s.Condition),
	}
}

// stringOrList decodes a JSON value that AWS allows to be either a
// single string or an array of strings.
func stringOrList(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	return nil
}

// flattenPrincipals normalises Principal / NotPrincipal which AWS
// accepts as either "*" (string), a map of {"AWS": "..."},
// {"Service": "..."}, etc., or an array shape per category.
func flattenPrincipals(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == "" {
			return nil
		}
		return []string{single}
	}
	var byCategory map[string]json.RawMessage
	if err := json.Unmarshal(raw, &byCategory); err != nil {
		return nil
	}
	categories := make([]string, 0, len(byCategory))
	for k := range byCategory {
		categories = append(categories, k)
	}
	sort.Strings(categories)
	var out []string
	for _, cat := range categories {
		for _, v := range stringOrList(byCategory[cat]) {
			out = append(out, cat+":"+v)
		}
	}
	return out
}

// flattenConditions expands AWS's nested
// {"Operator": {"Key": "Value"}} shape into one Condition per
// (operator, key) pair so consumers can iterate without
// re-traversing the map.
func flattenConditions(raw json.RawMessage) []Condition {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var byOperator map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &byOperator); err != nil {
		return nil
	}
	operators := make([]string, 0, len(byOperator))
	for op := range byOperator {
		operators = append(operators, op)
	}
	sort.Strings(operators)
	var out []Condition
	for _, op := range operators {
		entries := byOperator[op]
		keys := make([]string, 0, len(entries))
		for k := range entries {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, Condition{
				Operator: op,
				Key:      k,
				Values:   stringOrList(entries[k]),
			})
		}
	}
	return out
}

// distinctPrincipals collects the distinct AWS-category principals
// referenced by a trust policy's statements. Used to derive
// "X assumes Y" edges from role trust documents.
func distinctPrincipals(stmts []PolicyStatement) []string {
	seen := map[string]struct{}{}
	var out []string
	for i := range stmts {
		for _, p := range stmts[i].Principals {
			// Only AWS:<arn> principals can be subjects of an
			// assumes-edge — Service:<name> principals (lambda,
			// ec2) are AWS-internal callers, not assets in the
			// snapshot.
			if !strings.HasPrefix(p, "AWS:") {
				continue
			}
			arn := strings.TrimPrefix(p, "AWS:")
			if arn == "" || arn == "*" {
				continue
			}
			if _, dup := seen[arn]; dup {
				continue
			}
			seen[arn] = struct{}{}
			out = append(out, arn)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
