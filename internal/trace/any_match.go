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

	if rc.EvalCtx.PredicateParser == nil {
		return node
	}

	identities, ok := rc.FieldValue.([]asset.CloudIdentity)
	if !ok {
		return node
	}

	node.IdentityCount = len(identities)

	nestedPred, err := rc.EvalCtx.PredicateParser(rc.CompareValue)
	if err != nil {
		return node
	}

	for i, id := range identities {
		idCtx := policy.EvalContext{
			Properties:      id.Map(),
			Params:          rc.EvalCtx.Params,
			PredicateParser: rc.EvalCtx.PredicateParser,
		}
		nestedGroup := TracePredicate(*nestedPred, idCtx)
		if nestedGroup.Result {
			idx := i
			node.MatchedIndex = &idx
			node.MatchedID = id.ID.String()
			node.NestedTrace = nestedGroup
			node.Result = true
			return node
		}
	}

	return node
}
