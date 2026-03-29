package maps

import "testing"

var zeroValue Value

func TestParseMap_Get(t *testing.T) {
	v := ParseMap(map[string]any{"a": "hello", "b": 42})
	if v.Get("a").String() != "hello" {
		t.Fatalf("got %q", v.Get("a").String())
	}
	if v.Get("missing").IsMissing() != true {
		t.Fatal("expected missing")
	}
}

func TestValue_IsMissing(t *testing.T) {
	if !zeroValue.IsMissing() {
		t.Fatal("zero value should be missing")
	}
	if (Value{data: "x"}).IsMissing() {
		t.Fatal("non-nil should not be missing")
	}
}

func TestValue_GetMap(t *testing.T) {
	v := ParseMap(map[string]any{
		"nested": map[string]any{"key": "val"},
		"notmap": "string",
	})
	if v.GetMap("nested").Get("key").String() != "val" {
		t.Fatal("expected nested value")
	}
	// GetMap on a non-map key returns Value wrapping a typed nil map,
	// which is not IsMissing (typed nil != untyped nil). It is empty though.
	if v.GetMap("notmap").Get("anything").String() != "" {
		t.Fatal("non-map should have no children")
	}
	if v.GetMap("absent").Get("anything").String() != "" {
		t.Fatal("absent key should have no children")
	}
}

func TestValue_GetPath(t *testing.T) {
	v := ParseMap(map[string]any{
		"a": map[string]any{
			"b": map[string]any{
				"c": "deep",
			},
		},
	})
	if v.GetPath("a.b.c").String() != "deep" {
		t.Fatalf("got %q", v.GetPath("a.b.c").String())
	}
	if !v.GetPath("a.b.missing").IsMissing() {
		t.Fatal("expected missing for absent path")
	}
	if !v.GetPath("a.missing.c").IsMissing() {
		t.Fatal("expected missing for broken path")
	}
	if !v.GetPath("").IsMissing() {
		t.Fatal("empty path should return missing")
	}
	if !v.GetPath("  ").IsMissing() {
		t.Fatal("whitespace path should return missing")
	}
	if !v.GetPath("a..c").IsMissing() {
		t.Fatal("empty segment should return missing")
	}
}

func TestValue_Bool(t *testing.T) {
	if !(Value{data: true}).Bool() {
		t.Fatal("expected true")
	}
	if (Value{data: false}).Bool() {
		t.Fatal("expected false")
	}
	if (Value{data: "true"}).Bool() {
		t.Fatal("string should not parse as bool")
	}
	if (zeroValue).Bool() {
		t.Fatal("nil should be false")
	}
}

func TestValue_String(t *testing.T) {
	if (Value{data: "hello"}).String() != "hello" {
		t.Fatal("expected hello")
	}
	if (Value{data: "  trimmed  "}).String() != "trimmed" {
		t.Fatal("expected trimmed")
	}
	if (Value{data: 42}).String() != "" {
		t.Fatal("non-string should return empty")
	}
	if (zeroValue).String() != "" {
		t.Fatal("nil should return empty")
	}
}

func TestValue_Any(t *testing.T) {
	if (Value{data: 42}).Any() != 42 {
		t.Fatal("expected 42")
	}
	if (zeroValue).Any() != nil {
		t.Fatal("nil data should return nil")
	}
}

func TestValue_StringSlice(t *testing.T) {
	t.Run("from []any", func(t *testing.T) {
		v := Value{data: []any{"a", "b", "c"}}
		got := v.StringSlice()
		if len(got) != 3 || got[0] != "a" || got[2] != "c" {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("from []string", func(t *testing.T) {
		v := Value{data: []string{"x", "y"}}
		got := v.StringSlice()
		if len(got) != 2 || got[0] != "x" {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("trims and filters", func(t *testing.T) {
		v := Value{data: []any{"  a  ", "", "  ", "b"}}
		got := v.StringSlice()
		if len(got) != 2 || got[0] != "a" || got[1] != "b" {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("non-string items skipped", func(t *testing.T) {
		v := Value{data: []any{"a", 42, "b"}}
		got := v.StringSlice()
		if len(got) != 2 {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("nil returns nil", func(t *testing.T) {
		if (zeroValue).StringSlice() != nil {
			t.Fatal("expected nil")
		}
	})
	t.Run("wrong type returns nil", func(t *testing.T) {
		if (Value{data: 42}).StringSlice() != nil {
			t.Fatal("expected nil for int")
		}
	})
}

func TestValue_StringMap(t *testing.T) {
	t.Run("from map[string]any", func(t *testing.T) {
		v := Value{data: map[string]any{"k": "v", "num": 42}}
		got := v.StringMap()
		if got["k"] != "v" {
			t.Fatalf("got %v", got)
		}
		if _, ok := got["num"]; ok {
			t.Fatal("non-string value should be skipped")
		}
	})
	t.Run("from map[string]string", func(t *testing.T) {
		v := Value{data: map[string]string{"a": "b"}}
		got := v.StringMap()
		if got["a"] != "b" {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("trims keys and values", func(t *testing.T) {
		v := Value{data: map[string]any{" k ": " v "}}
		got := v.StringMap()
		if got["k"] != "v" {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("skips empty keys and values", func(t *testing.T) {
		v := Value{data: map[string]any{"": "v", "k": "", "  ": "v2"}}
		got := v.StringMap()
		if len(got) != 0 {
			t.Fatalf("expected empty, got %v", got)
		}
	})
	t.Run("wrong type returns empty", func(t *testing.T) {
		got := (Value{data: 42}).StringMap()
		if len(got) != 0 {
			t.Fatalf("expected empty, got %v", got)
		}
	})
}

func TestValue_asMap_nil(t *testing.T) {
	v := zeroValue
	m := v.asMap()
	if m == nil {
		t.Fatal("expected non-nil empty map")
	}
	if len(m) != 0 {
		t.Fatal("expected empty map")
	}
}
