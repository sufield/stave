package fp_test

import (
	"strconv"
	"testing"

	"github.com/sufield/stave/internal/pkg/fp"
)

func TestMap(t *testing.T) {
	tests := []struct {
		name  string
		input []int
		fn    func(int) string
		want  []string
	}{
		{"nil input", nil, strconv.Itoa, nil},
		{"empty input", []int{}, strconv.Itoa, nil},
		{"single element", []int{42}, strconv.Itoa, []string{"42"}},
		{"multiple elements", []int{1, 2, 3}, strconv.Itoa, []string{"1", "2", "3"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.Map(tt.input, tt.fn)
			assertStringSliceEqual(t, tt.want, got)
		})
	}
}

func TestFilter(t *testing.T) {
	isEven := func(n int) bool { return n%2 == 0 }
	tests := []struct {
		name  string
		input []int
		want  []int
	}{
		{"nil input", nil, nil},
		{"empty input", []int{}, nil},
		{"no matches", []int{1, 3, 5}, nil},
		{"all match", []int{2, 4, 6}, []int{2, 4, 6}},
		{"some match", []int{1, 2, 3, 4}, []int{2, 4}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.Filter(tt.input, isEven)
			assertIntSliceEqual(t, tt.want, got)
		})
	}
}

func TestCountFunc(t *testing.T) {
	isPositive := func(n int) bool { return n > 0 }
	tests := []struct {
		name  string
		input []int
		want  int
	}{
		{"nil input", nil, 0},
		{"empty input", []int{}, 0},
		{"no matches", []int{-1, -2}, 0},
		{"all match", []int{1, 2, 3}, 3},
		{"some match", []int{-1, 2, -3, 4}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.CountFunc(tt.input, isPositive)
			if got != tt.want {
				t.Errorf("CountFunc() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestToSet(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		got := fp.ToSet([]string(nil))
		if got != nil {
			t.Errorf("ToSet(nil) = %v, want nil", got)
		}
	})
	t.Run("empty input", func(t *testing.T) {
		got := fp.ToSet([]string{})
		if got != nil {
			t.Errorf("ToSet([]) = %v, want nil", got)
		}
	})
	t.Run("deduplicates", func(t *testing.T) {
		got := fp.ToSet([]string{"a", "b", "a"})
		if len(got) != 2 {
			t.Fatalf("ToSet() len = %d, want 2", len(got))
		}
		if _, ok := got["a"]; !ok {
			t.Error("missing key 'a'")
		}
		if _, ok := got["b"]; !ok {
			t.Error("missing key 'b'")
		}
	})
}

func TestToMap(t *testing.T) {
	type item struct {
		ID   string
		Name string
	}
	keyFn := func(i item) string { return i.ID }

	t.Run("nil input", func(t *testing.T) {
		got := fp.ToMap([]item(nil), keyFn)
		if got != nil {
			t.Errorf("ToMap(nil) = %v, want nil", got)
		}
	})
	t.Run("empty input", func(t *testing.T) {
		got := fp.ToMap([]item{}, keyFn)
		if got != nil {
			t.Errorf("ToMap([]) = %v, want nil", got)
		}
	})
	t.Run("multiple elements", func(t *testing.T) {
		items := []item{{ID: "a", Name: "Alice"}, {ID: "b", Name: "Bob"}}
		got := fp.ToMap(items, keyFn)
		if len(got) != 2 {
			t.Fatalf("ToMap() len = %d, want 2", len(got))
		}
		if got["a"].Name != "Alice" {
			t.Errorf("got[a].Name = %q, want Alice", got["a"].Name)
		}
		if got["b"].Name != "Bob" {
			t.Errorf("got[b].Name = %q, want Bob", got["b"].Name)
		}
	})
	t.Run("last writer wins on duplicate keys", func(t *testing.T) {
		items := []item{{ID: "a", Name: "First"}, {ID: "a", Name: "Second"}}
		got := fp.ToMap(items, keyFn)
		if len(got) != 1 {
			t.Fatalf("ToMap() len = %d, want 1", len(got))
		}
		if got["a"].Name != "Second" {
			t.Errorf("got[a].Name = %q, want Second", got["a"].Name)
		}
	})
}

func assertStringSliceEqual(t *testing.T, want, got []string) {
	t.Helper()
	if want == nil && got == nil {
		return
	}
	if want == nil || got == nil {
		t.Errorf("got %v, want %v", got, want)
		return
	}
	if len(want) != len(got) {
		t.Errorf("got len %d, want len %d", len(got), len(want))
		return
	}
	for i := range want {
		if want[i] != got[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func assertIntSliceEqual(t *testing.T, want, got []int) {
	t.Helper()
	if want == nil && got == nil {
		return
	}
	if want == nil || got == nil {
		t.Errorf("got %v, want %v", got, want)
		return
	}
	if len(want) != len(got) {
		t.Errorf("got len %d, want len %d", len(got), len(want))
		return
	}
	for i := range want {
		if want[i] != got[i] {
			t.Errorf("index %d: got %d, want %d", i, got[i], want[i])
		}
	}
}
