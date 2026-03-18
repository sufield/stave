package trace

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
)

// traceAnyMatchRule traces any_match logic by iterating through identities.
// Returns the concrete type so callers can access AnyMatchNode fields directly.
func traceAnyMatchRule(rc ruleContext) *AnyMatchNode {
	node := &AnyMatchNode{
		Index:        rc.Index,
		Field:        rc.Field,
		FieldExists:  rc.FieldExists,
		MatchedIndex: -1,
	}

	if !rc.FieldExists || rc.FieldValue == nil {
		return node
	}

	identities, ok := rc.FieldValue.([]asset.CloudIdentity)
	if !ok {
		return node
	}

	node.IdentityCount = len(identities)
	if node.IdentityCount == 0 {
		return node
	}

	nestedPred, err := rc.EvalCtx.ParsePredicate(rc.CompareValue)
	if err != nil || nestedPred == nil {
		return node
	}

	baseCtx := policy.EvalContext{
		Params:          rc.EvalCtx.Params,
		PredicateParser: rc.EvalCtx.PredicateParser,
	}
	for i, id := range identities {
		idCtx := baseCtx
		idCtx.Properties = id.Map()

		nestedTrace := TracePredicate(*nestedPred, idCtx)
		if nestedTrace.Result {
			node.Result = true
			node.MatchedIndex = i
			node.MatchedID = id.ID
			node.NestedTrace = nestedTrace
			return node
		}
	}

	return node
}
