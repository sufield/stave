package predicate

import (
	"encoding/json"
	"testing"
)

func FuzzEvaluateOperator(f *testing.F) {
	type seed struct {
		op         string
		fieldVal   string // JSON-encoded value
		compareVal string // JSON-encoded value
	}
	seeds := []seed{
		{"eq", `"hello"`, `"hello"`},
		{"eq", `true`, `true`},
		{"eq", `false`, `true`},
		{"ne", `"a"`, `"b"`},
		{"gt", `10`, `5`},
		{"lt", `3`, `7`},
		{"gte", `5`, `5`},
		{"lte", `5`, `5`},
		{"missing", `null`, `null`},
		{"present", `"x"`, `null`},
		{"in", `"a"`, `["a","b","c"]`},
		{"contains", `"hello world"`, `"world"`},
		{"list_empty", `[]`, `null`},
		{"eq", `null`, `null`},
		{"unknown_op", `"x"`, `"y"`},
	}
	for _, s := range seeds {
		f.Add(s.op, s.fieldVal, s.compareVal)
	}

	f.Fuzz(func(t *testing.T, op, fieldValJSON, compareValJSON string) {
		var fieldVal, compareVal any
		json.Unmarshal([]byte(fieldValJSON), &fieldVal)
		json.Unmarshal([]byte(compareValJSON), &compareVal)

		fieldExists := fieldVal != nil
		EvaluateOperator(op, fieldExists, fieldVal, compareVal)
	})
}
