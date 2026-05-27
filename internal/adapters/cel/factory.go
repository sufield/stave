package cel

import (
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// NewPredicateEval creates a policy.PredicateEval backed by the CEL engine.
// The returned function compiles predicates on first use and caches them.
//
// No-arg shape preserved so callers that pass NewPredicateEval as a
// `func() (PredicateEval, error)` factory value (CELEvaluatorFactory)
// keep compiling. Cache-aware callers use NewPredicateEvalWithCompiler.
func NewPredicateEval() (policy.PredicateEval, error) {
	compiler, err := NewCompiler()
	if err != nil {
		return nil, err
	}
	return wrapEval(compiler), nil
}

// NewPredicateEvalWithCompiler is the cache-aware shape: pass
// CompilerOption values (e.g. WithCacheDir) to enable the on-disk
// compile cache. Returns the Compiler so the caller can call
// PersistCache at shutdown to extend the cache file with any
// newly-compiled predicates.
func NewPredicateEvalWithCompiler(opts ...CompilerOption) (policy.PredicateEval, *Compiler, error) {
	compiler, err := NewCompiler(opts...)
	if err != nil {
		return nil, nil, err
	}
	return wrapEval(compiler), compiler, nil
}

// wrapEval is the shared closure body — promoted to a free function
// so the two factory shapes above cannot drift on the eval
// semantics. Any future per-call logic (tracing, metrics, fallback)
// lands here once and reaches both callers.
func wrapEval(compiler *Compiler) policy.PredicateEval {
	return func(ctl policy.ControlDefinition, a asset.Asset, identities []asset.CloudIdentity) (bool, error) {
		cp, compileErr := compiler.Compile(ctl.UnsafePredicate)
		if compileErr != nil {
			return false, compileErr
		}
		return Evaluate(cp, a, identities, ctl.Params.Raw())
	}
}

// MustPredicateEval creates a PredicateEval or panics. For use in tests only.
func MustPredicateEval() policy.PredicateEval {
	eval, err := NewPredicateEval()
	if err != nil {
		panic("MustPredicateEval: " + err.Error())
	}
	return eval
}
