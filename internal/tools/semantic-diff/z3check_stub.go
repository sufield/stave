//go:build !(cgo && z3)

package main

import (
	policy "github.com/sufield/stave/internal/core/controldef"
)

func symbolicCheckImpl(_ policy.UnsafePredicate, _ []fieldInfo) symbolicResult {
	return symbolicResult{Status: "SKIP", Detail: "Z3 not available (build with -tags z3)"}
}
