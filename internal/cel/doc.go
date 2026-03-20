// Package cel provides a CEL-based predicate evaluator for the ctrl.v1 control
// DSL.
//
// The [Compiler] translates ctrl.v1 UnsafePredicate structures into compiled
// CEL programs. [Evaluate] and [EvaluateWithParams] execute these programs
// against asset properties and optional control parameters.
package cel
