package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

// fieldCache maps struct types to their JSON tag → field index mappings,
// avoiding O(n) reflection lookups on every field access.
var fieldCache sync.Map // map[reflect.Type]map[string]int

// executeTemplate renders a simple field-substitution template against data.
//
// Supported syntax:
//   - {{.FieldName}}          — access a top-level field
//   - {{.Nested.FieldName}}   — access nested fields
//   - {{range .Slice}}...{{end}} — iterate over slices; within the body,
//     {{.Field}} refers to the current element
//   - {{json .Field}}         — JSON-encode a field value
//   - {{"\n"}}                — literal newline
//
// This intentionally avoids Go's text/template to comply with the banned-imports
// policy (no arbitrary code execution via templates).
func ExecuteTemplate(w io.Writer, tmplStr string, data any) error {
	output, err := renderTemplate(tmplStr, data, 0)
	if err != nil {
		return fmt.Errorf("template error: %w", err)
	}
	_, err = io.WriteString(w, output)
	return err
}

// maxTemplateDepth caps nested {{range}} recursion to prevent stack overflow
// from malicious or malformed templates.
const maxTemplateDepth = 10

func renderTemplate(tmpl string, data any, depth int) (string, error) {
	if depth > maxTemplateDepth {
		return "", fmt.Errorf("template nesting exceeds maximum depth of %d", maxTemplateDepth)
	}
	var b strings.Builder
	rest := tmpl
	for rest != "" {
		renderedRange, remaining, handled, err := renderRangeSegment(rest, data, depth)
		if err != nil {
			return "", err
		}
		if handled {
			b.WriteString(renderedRange)
			rest = remaining
			continue
		}

		renderedExpr, remaining, done, err := renderExpressionSegment(rest, data)
		if err != nil {
			return "", err
		}
		b.WriteString(renderedExpr)
		if done {
			break
		}
		rest = remaining
	}
	return b.String(), nil
}

func renderRangeSegment(rest string, data any, depth int) (string, string, bool, error) {
	rangeIdx := strings.Index(rest, "{{range ")
	exprIdx := strings.Index(rest, "{{")
	if rangeIdx < 0 || (exprIdx >= 0 && rangeIdx > exprIdx) {
		return "", rest, false, nil
	}

	var b strings.Builder
	b.WriteString(rest[:rangeIdx])

	fieldExpr, body, remaining, err := parseRangeBlock(rest[rangeIdx:])
	if err != nil {
		return "", "", false, err
	}
	rendered, err := renderRangeBody(fieldExpr, body, data, depth)
	if err != nil {
		return "", "", false, err
	}
	b.WriteString(rendered)
	return b.String(), remaining, true, nil
}

func parseRangeBlock(rest string) (string, string, string, error) {
	rangeEnd := strings.Index(rest, "}}")
	if rangeEnd < 0 {
		return "", "", "", fmt.Errorf("unclosed {{range}}")
	}
	fieldExpr := strings.TrimSpace(rest[len("{{range "):rangeEnd])
	remaining := rest[rangeEnd+2:]
	before, after, ok := strings.Cut(remaining, "{{end}}")
	if !ok {
		return "", "", "", fmt.Errorf("missing {{end}} for {{range}}")
	}
	body := before
	return fieldExpr, body, after, nil
}

func renderRangeBody(fieldExpr, body string, data any, depth int) (string, error) {
	val, err := resolveField(data, fieldExpr)
	if err != nil {
		return "", fmt.Errorf("range %s: %w", fieldExpr, err)
	}
	rv := reflect.ValueOf(val)
	if rv.Kind() != reflect.Slice {
		return "", fmt.Errorf("range %s: not a slice (got %T)", fieldExpr, val)
	}

	var b strings.Builder
	for i := 0; i < rv.Len(); i++ {
		elem := rv.Index(i).Interface()
		rendered, renderErr := renderTemplate(body, elem, depth+1)
		if renderErr != nil {
			return "", fmt.Errorf("range %s[%d]: %w", fieldExpr, i, renderErr)
		}
		b.WriteString(rendered)
	}
	return b.String(), nil
}

func renderExpressionSegment(rest string, data any) (string, string, bool, error) {
	exprIdx := strings.Index(rest, "{{")
	if exprIdx < 0 {
		return rest, "", true, nil
	}

	var b strings.Builder
	b.WriteString(rest[:exprIdx])
	expr, remaining, err := parseExpression(rest[exprIdx:], exprIdx)
	if err != nil {
		return "", "", false, err
	}
	rendered, err := renderExpression(expr, data)
	if err != nil {
		return "", "", false, err
	}
	b.WriteString(rendered)
	return b.String(), remaining, false, nil
}

func parseExpression(rest string, exprIdx int) (string, string, error) {
	closeIdx := strings.Index(rest, "}}")
	if closeIdx < 0 {
		return "", "", fmt.Errorf("unclosed {{ at position %d", exprIdx)
	}
	expr := strings.TrimSpace(rest[2:closeIdx])
	return expr, rest[closeIdx+2:], nil
}

func renderExpression(expr string, data any) (string, error) {
	switch {
	case expr == `"\n"`:
		return "\n", nil
	case strings.HasPrefix(expr, "json "):
		fieldExpr := strings.TrimSpace(expr[5:])
		val, err := resolveField(data, fieldExpr)
		if err != nil {
			return "", err
		}
		jsonBytes, err := json.MarshalIndent(val, "", "  ")
		if err != nil {
			return "", fmt.Errorf("json %s: %w", fieldExpr, err)
		}
		return string(jsonBytes), nil
	default:
		val, err := resolveField(data, expr)
		if err != nil {
			return "", err
		}
		return formatValue(val), nil
	}
}

// resolveField resolves a dot-path like ".Summary.Violations" against data.
func resolveField(data any, expr string) (any, error) {
	expr = strings.Trim(expr, ".")
	if expr == "" {
		return data, nil
	}

	current := reflect.ValueOf(data)
	for part := range strings.SplitSeq(expr, ".") {
		if part == "" {
			continue
		}
		next, err := resolveFieldPart(current, part, expr)
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current.Interface(), nil
}

func resolveFieldPart(current reflect.Value, part, expr string) (reflect.Value, error) {
	deref, err := dereferenceValue(current, expr)
	if err != nil {
		return reflect.Value{}, err
	}

	switch deref.Kind() {
	case reflect.Struct:
		field := deref.FieldByName(part)
		if field.IsValid() {
			return field, nil
		}
		field = findFieldByJSONTag(deref, part)
		if field.IsValid() {
			return field, nil
		}
		return reflect.Value{}, fmt.Errorf("field %q not found in %s", part, deref.Type())
	case reflect.Map:
		mapValue := deref.MapIndex(reflect.ValueOf(part))
		if !mapValue.IsValid() {
			return reflect.Value{}, fmt.Errorf("key %q not found in map", part)
		}
		return mapValue, nil
	default:
		return reflect.Value{}, fmt.Errorf("cannot access %q on %s", part, deref.Type())
	}
}

func dereferenceValue(current reflect.Value, expr string) (reflect.Value, error) {
	if !current.IsValid() {
		return reflect.Value{}, fmt.Errorf("cannot resolve %q: nil value", expr)
	}
	for current.Kind() == reflect.Pointer {
		if current.IsNil() {
			return reflect.Value{}, fmt.Errorf("cannot resolve %q: nil pointer", expr)
		}
		current = current.Elem()
	}
	return current, nil
}

func findFieldByJSONTag(v reflect.Value, tag string) reflect.Value {
	typ := v.Type()

	var mapping map[string]int
	if cached, ok := fieldCache.Load(typ); ok {
		mapping = cached.(map[string]int)
	} else {
		mapping = make(map[string]int, typ.NumField())
		for i := range typ.NumField() {
			jt, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
			if jt != "" && jt != "-" {
				mapping[jt] = i
			}
		}
		fieldCache.Store(typ, mapping)
	}

	if idx, ok := mapping[tag]; ok {
		return v.Field(idx)
	}
	return reflect.Value{}
}

func formatValue(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case bool:
		return strconv.FormatBool(val)
	case float32:
		return formatFloatValue(float64(val))
	case float64:
		return formatFloatValue(val)
	case time.Time:
		return val.Format(time.RFC3339)
	case fmt.Stringer:
		return val.String()
	default:
		if n, ok := formatIntegerValue(v); ok {
			return n
		}
		return fmt.Sprintf("%v", v)
	}
}

func formatFloatValue(val float64) string {
	if val == float64(int64(val)) {
		return strconv.FormatInt(int64(val), 10)
	}
	return fmt.Sprintf("%.1f", val)
}

func formatIntegerValue(v any) (string, bool) {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(rv.Int(), 10), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(rv.Uint(), 10), true
	default:
		return "", false
	}
}
