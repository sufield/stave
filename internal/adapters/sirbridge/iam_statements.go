package sirbridge

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/sir"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
)

// extractIAMStatementsForAsset returns the IAM-policy statements
// from `identities` that target the specified bucket asset.
// Used by the L4 grouper to populate
// ResourceFactGroup.AttachedIAM.
//
// Filter heuristic: a statement is included when ANY of its
// `Resource` values is one of the following exact strings:
//   - the bucket's ARN ("arn:aws:s3:::my-bucket")
//   - the bucket's ARN suffixed with "/*" ("arn:aws:s3:::my-bucket/*")
//   - the wildcard "*"
//
// `NotResource` is treated similarly — when a statement names this
// bucket via NotResource, the solver still needs to see it
// (NotResource semantics are solver work). The filter is
// intentionally conservative: false positives are cheap, false
// negatives are not.
//
// StringLike / glob patterns (e.g. "arn:aws:s3:::my-*") are
// emitted verbatim as the literal Resource string. The solver
// in L6 decides what string patterns mean — Stave does NOT
// expand them here.
//
// Iter L2 contract: zero logical reasoning. The extractor reads
// raw IAM policy JSON, decodes it via the existing iam package,
// and emits per-statement facts. Effect, Principals, Conditions
// are passed through; whether a statement actually grants
// access depends on cross-policy interaction (solver work in
// L6).
func extractIAMStatementsForAsset(bucket asset.Asset, identities []asset.CloudIdentity) []sir.IAMPolicyStatementFact {
	if len(identities) == 0 {
		return nil
	}
	bucketARN := string(bucket.ID)
	bucketARNObjects := bucketARN + "/*"

	out := make([]sir.IAMPolicyStatementFact, 0)
	for i := range identities {
		id := &identities[i]
		policiesJSON := iamPolicyJSON(id)
		if policiesJSON == "" {
			continue
		}
		doc, err := iam.ParsePolicyDocument(policiesJSON)
		if err != nil {
			continue
		}
		for j := range doc.Statement {
			stmt := &doc.Statement[j]
			if !statementTargetsAsset(stmt, bucketARN, bucketARNObjects) {
				continue
			}
			fact := sir.IAMPolicyStatementFact{
				StatementIndex: j,
				Effect:         string(stmt.Effect),
				Actions:        append([]string{}, stmt.Action...),
				Resources:      append([]string{}, stmt.Resource...),
				Conditions:     iamConditionFacts(stmt.Condition, string(id.ID), j),
				AttachedTo: &sir.TypedPrincipal{
					Kind:  identityKind(id),
					Value: string(id.ID),
				},
				Source: sir.SourceRef{
					Kind: "iam_statement",
					ID:   string(id.ID),
					Path: []string{"IAMPolicy", iamPolicyName(id), "Statement", strconv.Itoa(j)},
				},
			}
			out = append(out, fact)
		}
	}
	return out
}

// statementTargetsAsset is the conservative filter described in
// the function header. Returns true when ANY Resource or
// NotResource value in the statement matches the bucket via
// the literal-match rules.
func statementTargetsAsset(stmt *iam.Statement, bucketARN, bucketARNObjects string) bool {
	for _, r := range stmt.Resource {
		if matchesAssetARN(r, bucketARN, bucketARNObjects) {
			return true
		}
	}
	return false
}

func matchesAssetARN(value, bucketARN, bucketARNObjects string) bool {
	if value == "*" {
		return true
	}
	if value == bucketARN || value == bucketARNObjects {
		return true
	}
	return false
}

// iamPolicyJSON extracts the identity's policies JSON blob
// from asset.Properties using the same path the rest of the
// IAM pipeline uses (identity.policies_json). Returns "" when
// absent.
func iamPolicyJSON(id *asset.CloudIdentity) string {
	raw, hasIdentity := id.Properties["identity"]
	if !hasIdentity || raw == nil {
		return ""
	}
	identityMap, ok := raw.(map[string]any)
	if !ok {
		// Surface the schema mismatch instead of returning ""
		// silently. Pre-fix, an `identity` field stored as a
		// string or list (collector bugs) caused every IAM
		// statement extraction for that principal to be empty
		// with no diagnostic.
		slog.Warn("identity property has unexpected type — skipping policy extraction",
			"principal_id", string(id.ID),
			"actual_type", typeName(raw))
		return ""
	}
	jsonRaw, hasJSON := identityMap["policies_json"]
	if !hasJSON || jsonRaw == nil {
		return ""
	}
	s, ok := jsonRaw.(string)
	if !ok {
		slog.Warn("identity.policies_json has unexpected type — skipping",
			"principal_id", string(id.ID),
			"actual_type", typeName(jsonRaw))
		return ""
	}
	return s
}

// iamPolicyName produces the policy-name segment of the
// SourceRef path. The asset model doesn't currently expose a
// policy name distinct from the policies_json blob; we use the
// principal type segment of the ID (e.g. "role/AppRole" from
// "arn:aws:iam::111122223333:role/AppRole") so the path is
// human-readable. A future asset-model extension that exposes
// per-policy ARNs replaces this single edit site.
func iamPolicyName(id *asset.CloudIdentity) string {
	idStr := string(id.ID)
	idx := strings.LastIndex(idStr, ":")
	if idx < 0 || idx+1 >= len(idStr) {
		return idStr
	}
	return idStr[idx+1:]
}

// identityKind translates the asset CloudIdentity Type into a
// TypedPrincipal Kind. The type strings that flow in are the
// same the IAM resolver consumes (aws_iam_role,
// aws_iam_user, etc.); collapse them onto the AWS Principal
// vocabulary the rest of the SIR uses.
func identityKind(id *asset.CloudIdentity) string {
	switch string(id.Type) {
	case "aws_iam_role":
		return "AWS_Role"
	case "aws_iam_user":
		return "AWS_User"
	case "aws_iam_group":
		return "AWS_Group"
	default:
		return "AWS"
	}
}

// iamConditionFacts decodes an iam.Statement.Condition (typed
// as `any` because the IAM package didn't normalize it) into
// the SIR's flat ConditionFact slice. Tolerates the standard
// AWS shape: map[string]map[string]string|[]string. Anything
// else returns nil.
func iamConditionFacts(rawCondition any, identityID string, statementIndex int) []sir.ConditionFact {
	conds, ok := rawCondition.(map[string]any)
	if !ok || len(conds) == 0 {
		return nil
	}
	var out []sir.ConditionFact
	for op, byKey := range conds {
		keyMap, ok := byKey.(map[string]any)
		if !ok {
			continue
		}
		for key, raw := range keyMap {
			values := iamConditionValues(raw)
			out = append(out, sir.ConditionFact{
				Operator: op,
				Key:      key,
				Values:   values,
				Source: sir.SourceRef{
					Kind: "condition",
					ID:   identityID,
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

// iamConditionValues coerces an AWS condition leaf (which can
// be string, []any of strings, bool, or number) into the SIR's
// []string. Bools and numbers stringify with strconv to keep
// the wire shape stable across operators.
func iamConditionValues(raw any) []string {
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case bool:
		return []string{strconv.FormatBool(v)}
	case float64:
		return []string{strconv.FormatFloat(v, 'f', -1, 64)}
	default:
		return nil
	}
}
