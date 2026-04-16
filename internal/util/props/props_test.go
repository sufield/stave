package props

import "testing"

func TestGetIn_NestedString(t *testing.T) {
	m := map[string]any{
		"storage": map[string]any{
			"encryption": map[string]any{
				"algorithm": "AES256",
			},
		},
	}
	v, ok := GetIn[string](m, []string{"storage", "encryption", "algorithm"})
	if !ok || v != "AES256" {
		t.Errorf("got %q, %v; want AES256, true", v, ok)
	}
}

func TestGetIn_MissingKey(t *testing.T) {
	m := map[string]any{"a": map[string]any{"b": "val"}}
	v, ok := GetIn[string](m, []string{"a", "missing"})
	if ok || v != "" {
		t.Errorf("got %q, %v; want '', false", v, ok)
	}
}

func TestGetIn_WrongType(t *testing.T) {
	m := map[string]any{"x": 42}
	v, ok := GetIn[string](m, []string{"x"})
	if ok || v != "" {
		t.Errorf("got %q, %v; want '', false (int not string)", v, ok)
	}
}

func TestGetBool_True(t *testing.T) {
	m := map[string]any{"enabled": true}
	if !GetBool(m, []string{"enabled"}) {
		t.Error("expected true")
	}
}

func TestGetString_Empty(t *testing.T) {
	m := map[string]any{}
	if GetString(m, []string{"missing"}) != "" {
		t.Error("missing key should return empty string")
	}
}
