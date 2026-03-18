package trace

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
)

// traceAnyMatchRule traces any_match with identity iteration.
func traceAnyMatchRule(rc ruleContext) Node {
	node := &AnyMatchNode{
		Index:       rc.Index,
		Field:       rc.Field,
		FieldExists: rc.FieldExists,
	}

	if !rc.FieldExists {
		return node
	}

	identities, ok := rc.FieldValue.([]asset.CloudIdentity)
	if !ok {
		return node
	}

	node.IdentityCount = len(identities)

	nestedPred, err := rc.EvalCtx.ParsePredicate(rc.CompareValue)
	if nestedPred == nil || err != nil {
		return node
	}

	idCtx := policy.EvalContext{
		Params:          rc.EvalCtx.Params,
		PredicateParser: rc.EvalCtx.PredicateParser,
	}
	for i, id := range identities {
		idCtx.Properties = id.Map()
		nestedGroup := TracePredicate(*nestedPred, idCtx)
		if nestedGroup.Result {
			node.MatchedIndex = &i // safe: loop vars are per-iteration in Go 1.22+
			node.MatchedID = id.ID
			node.NestedTrace = nestedGroup
			node.Result = true
			return node
		}
	}

	return node
}
