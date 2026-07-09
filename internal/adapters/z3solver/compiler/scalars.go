//go:build cgo && z3

package compiler

import "fmt"

func scalarStringFmt(v any) string {
	return fmt.Sprintf("%v", v)
}
