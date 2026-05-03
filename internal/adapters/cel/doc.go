// Package cel provides a CEL-based predicate evaluator for the ctrl.v1 control
// DSL.
//
// The [Compiler] translates ctrl.v1 UnsafePredicate structures into compiled
// CEL programs. [Evaluate] executes these programs against asset properties.
package cel
