package cel

// EvalVersion identifies the evaluation semantics of the Stave CEL evaluator.
// Increment when evaluation behavior changes (e.g., new operators, changed
// missing-field handling, coercion rules) — even if predicate syntax stays
// the same. Used in FingerprintPolicy to detect evaluator swaps.
const EvalVersion = "stave-cel/1.0"
