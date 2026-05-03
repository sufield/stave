package compiler

import "fmt"

// scalarStringFmt is the slow-path fallback used by
// scalarString. Lifted into its own file so the hot-path
// switch in scalarString does not need to import "fmt".
func scalarStringFmt(v any) string {
	return fmt.Sprintf("%v", v)
}
