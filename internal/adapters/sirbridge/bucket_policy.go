package sirbridge

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/sir"
	"github.com/sufield/stave/internal/platform/providers/aws/s3/policy"
)

// readBucketPolicyJSON pulls the `policy_json` field from an
// asset's properties, surfacing a warning when the field exists
// but is the wrong type. Pre-fix the silent type assertion
// dropped malformed values into "no policy" — bucket policies
// stored as []byte or numbers (collector bugs in production
// traces) silently disappeared instead of being flagged.
func readBucketPolicyJSON(a asset.Asset) string {
	raw, ok := a.Properties["policy_json"]
	if !ok || raw == nil {
		return ""
	}
	s, isString := raw.(string)
	if !isString {
		slog.Warn("bucket policy_json has unexpected type — skipping",
			"asset_id", string(a.ID),
			"actual_type", typeName(raw))
		return ""
	}
	return s
}

// typeName produces a short type label for slog warnings without
// pulling in reflect for hot paths.
func typeName(v any) string {
	switch v.(type) {
	case string:
		return "string"
	case []byte:
		return "[]byte"
	case map[string]any:
		return "map[string]any"
	case []any:
		return "[]any"
	case bool:
		return "bool"
	case float64:
		return "float64"
	case nil:
		return "nil"
	default:
		return "unknown"
	}
}

// extractBucketPolicyStatements decodes the bucket policy JSON
// stored at asset.Properties["policy_json"] and emits one
// sir.BucketPolicyStatementFact per statement.
//
// Tolerant of ABSENT data: no policy_json (or an empty policy with
// zero statements) returns (nil, nil) — "no policy" is a valid state.
//
// Fail-loud on MALFORMED data: a policy_json that is present but does
// not parse returns an error rather than silently producing zero
// statement facts. A swallowed parse error would erase a possibly
// public statement and make the bucket look private to the L6 solver —
// the exact fail-open this guards against.
//
// Iter L1 contract: ZERO logical reasoning. The extractor decomposes
// AWS's polymorphic Principal / Action / Resource / Condition
// shapes into the SIR's flat typed slices and stops there. Whether
// a statement actually grants public access depends on Effect,
// conditions, and other statements — that's solver work in L6.
//
// SourceRef paths:
//   - Statement: ["Statement", strconv.Itoa(i)]
//   - Condition: ["Statement", strconv.Itoa(i), "Condition", op, key]
//
// StatementIndex is the zero-based position in the original
// `Statement` array. Stability of this index is part of the
// SourceRef contract; downstream consumers (the L7 fix
// suggester, the explainer) navigate to specific statements
// via the index.
func extractBucketPolicyStatements(a asset.Asset) ([]sir.BucketPolicyStatementFact, error) {
	policyJSON := readBucketPolicyJSON(a)
	if policyJSON == "" {
		return nil, nil
	}
	doc, err := policy.Parse(policyJSON)
	if err != nil {
		return nil, fmt.Errorf("bucket %s: policy_json present but unparseable — refusing to drop it, could hide a public statement: %w", a.ID, err)
	}
	if doc == nil {
		return nil, nil
	}
	stmts := doc.Statements()
	if len(stmts) == 0 {
		return nil, nil
	}
	bucketID := string(a.ID)

	out := make([]sir.BucketPolicyStatementFact, 0, len(stmts))
	for i := range stmts {
		stmt := &stmts[i]
		fact := sir.BucketPolicyStatementFact{
			StatementIndex: i,
			Sid:            stmt.Sid,
			Effect:         string(stmt.Effect),
			Principals:     typedPrincipalsFrom(&stmt.Principal),
			Actions:        append([]string{}, []string(stmt.Action)...),
			Resources:      append([]string{}, []string(stmt.Resource)...),
			Conditions:     conditionFactsFrom(stmt.Condition, bucketID, i),
			Source: sir.SourceRef{
				Kind: "statement",
				ID:   bucketID,
				Path: []string{"Statement", strconv.Itoa(i)},
			},
		}
		out = append(out, fact)
	}
	return out, nil
}

// typedPrincipalsFrom decomposes a NormalizedPrincipal into a
// flat slice of TypedPrincipal entries — one per concrete ARN /
// service / federated / canonical-user value, plus a single
// Wildcard entry when the bare "*" form was present.
//
// IsPublic is set strictly for the Wildcard entry and for any
// AWS-list entry whose value is literally "*". No other
// "is this public" inference happens here.
func typedPrincipalsFrom(p *policy.NormalizedPrincipal) []sir.TypedPrincipal {
	if p == nil {
		return nil
	}
	var out []sir.TypedPrincipal
	if p.Wildcard {
		out = append(out, sir.TypedPrincipal{
			Kind:     "Wildcard",
			Value:    "*",
			IsPublic: true,
		})
	}
	for _, arn := range p.AWSARNs {
		out = append(out, sir.TypedPrincipal{
			Kind:     "AWS",
			Value:    arn,
			IsPublic: arn == "*",
		})
	}
	for _, svc := range p.Services {
		out = append(out, sir.TypedPrincipal{Kind: "Service", Value: svc})
	}
	for _, fed := range p.Federated {
		out = append(out, sir.TypedPrincipal{Kind: "Federated", Value: fed})
	}
	for _, cu := range p.CanonicalUsers {
		out = append(out, sir.TypedPrincipal{Kind: "CanonicalUser", Value: cu})
	}
	return out
}

// conditionFactsFrom decomposes a NormalizedCondition (a
// map[op]map[key][]string) into a flat slice of ConditionFact
// triples. Each fact carries a SourceRef whose Path identifies
// the originating (operator, key) pair so the solver / explainer
// can navigate to the exact entry within the Condition block.
func conditionFactsFrom(cond policy.NormalizedCondition, bucketID string, statementIndex int) []sir.ConditionFact {
	if len(cond) == 0 {
		return nil
	}
	var out []sir.ConditionFact
	for op, byKey := range cond {
		for key, values := range byKey {
			out = append(out, sir.ConditionFact{
				Operator: op,
				Key:      key,
				Values:   append([]string{}, values...),
				Source: sir.SourceRef{
					Kind: "condition",
					ID:   bucketID,
					Path: []string{
						"Statement", strconv.Itoa(statementIndex),
						"Condition", op, key,
					},
				},
			})
		}
	}
	return out
}
