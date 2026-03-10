package fp_test

import (
	"slices"
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

func TestFilterMap(t *testing.T) {
	// Parse positive ints, skip non-positive
	posStr := func(n int) (string, bool) {
		if n > 0 {
			return strconv.Itoa(n), true
		}
		return "", false
	}
	tests := []struct {
		name  string
		input []int
		want  []string
	}{
		{"nil input", nil, nil},
		{"empty input", []int{}, nil},
		{"no matches", []int{-1, 0, -3}, nil},
		{"all match", []int{1, 2, 3}, []string{"1", "2", "3"}},
		{"some match", []int{-1, 2, -3, 4}, []string{"2", "4"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.FilterMap(tt.input, posStr)
			assertStringSliceEqual(t, tt.want, got)
		})
	}
}

func TestFlatMap(t *testing.T) {
	expand := func(n int) []int { return []int{n, n * 10} }
	tests := []struct {
		name  string
		input []int
		want  []int
	}{
		{"nil input", nil, nil},
		{"empty input", []int{}, nil},
		{"single element", []int{1}, []int{1, 10}},
		{"multiple elements", []int{1, 2}, []int{1, 10, 2, 20}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.FlatMap(tt.input, expand)
			assertIntSliceEqual(t, tt.want, got)
		})
	}
}

func TestFlatten(t *testing.T) {
	tests := []struct {
		name  string
		input [][]int
		want  []int
	}{
		{"nil input", nil, nil},
		{"empty input", [][]int{}, nil},
		{"single group", [][]int{{1, 2}}, []int{1, 2}},
		{"multiple groups", [][]int{{1}, {2, 3}, {4}}, []int{1, 2, 3, 4}},
		{"with empty groups", [][]int{{1}, {}, {3}}, []int{1, 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.Flatten(tt.input)
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

func TestFindFunc(t *testing.T) {
	isNeg := func(n int) bool { return n < 0 }

	t.Run("nil input", func(t *testing.T) {
		_, ok := fp.FindFunc([]int(nil), isNeg)
		if ok {
			t.Error("FindFunc(nil) should return false")
		}
	})
	t.Run("no match", func(t *testing.T) {
		_, ok := fp.FindFunc([]int{1, 2, 3}, isNeg)
		if ok {
			t.Error("expected no match")
		}
	})
	t.Run("finds first", func(t *testing.T) {
		got, ok := fp.FindFunc([]int{1, -2, -3}, isNeg)
		if !ok {
			t.Fatal("expected match")
		}
		if got != -2 {
			t.Errorf("FindFunc() = %d, want -2", got)
		}
	})
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

func TestGroupBy(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		got := fp.GroupBy([]int(nil), func(n int) string { return "" })
		if got != nil {
			t.Errorf("GroupBy(nil) = %v, want nil", got)
		}
	})
	t.Run("groups by parity", func(t *testing.T) {
		parity := func(n int) string {
			if n%2 == 0 {
				return "even"
			}
			return "odd"
		}
		got := fp.GroupBy([]int{1, 2, 3, 4, 5}, parity)
		if len(got) != 2 {
			t.Fatalf("GroupBy() groups = %d, want 2", len(got))
		}
		assertIntSliceEqual(t, []int{1, 3, 5}, got["odd"])
		assertIntSliceEqual(t, []int{2, 4}, got["even"])
	})
	t.Run("single group", func(t *testing.T) {
		got := fp.GroupBy([]int{2, 4, 6}, func(int) string { return "all" })
		if len(got) != 1 {
			t.Fatalf("GroupBy() groups = %d, want 1", len(got))
		}
		assertIntSliceEqual(t, []int{2, 4, 6}, got["all"])
	})
}

func TestMapKeys(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		got := fp.MapKeys(map[string]int(nil))
		if got != nil {
			t.Errorf("MapKeys(nil) = %v, want nil", got)
		}
	})
	t.Run("empty input", func(t *testing.T) {
		got := fp.MapKeys(map[string]int{})
		if got != nil {
			t.Errorf("MapKeys({}) = %v, want nil", got)
		}
	})
	t.Run("extracts keys", func(t *testing.T) {
		got := fp.MapKeys(map[string]int{"a": 1, "b": 2, "c": 3})
		slices.Sort(got) // map iteration order is non-deterministic
		assertStringSliceEqual(t, []string{"a", "b", "c"}, got)
	})
}

func TestSortedKeys(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		got := fp.SortedKeys(map[string]int(nil))
		if got != nil {
			t.Errorf("SortedKeys(nil) = %v, want nil", got)
		}
	})
	t.Run("returns sorted keys", func(t *testing.T) {
		got := fp.SortedKeys(map[string]int{"c": 3, "a": 1, "b": 2})
		assertStringSliceEqual(t, []string{"a", "b", "c"}, got)
	})
	t.Run("integer keys", func(t *testing.T) {
		got := fp.SortedKeys(map[int]string{3: "c", 1: "a", 2: "b"})
		assertIntSliceEqual(t, []int{1, 2, 3}, got)
	})
}

func TestDedupe(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{"nil input", nil, nil},
		{"empty input", []string{}, nil},
		{"no dupes", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"with dupes", []string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{"all same", []string{"x", "x", "x"}, []string{"x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fp.Dedupe(tt.input)
			assertStringSliceEqual(t, tt.want, got)
		})
	}
}

func TestZip(t *testing.T) {
	t.Run("nil inputs", func(t *testing.T) {
		got := fp.Zip([]int(nil), []string(nil))
		if got != nil {
			t.Errorf("Zip(nil, nil) = %v, want nil", got)
		}
	})
	t.Run("equal length", func(t *testing.T) {
		got := fp.Zip([]int{1, 2, 3}, []string{"a", "b", "c"})
		if len(got) != 3 {
			t.Fatalf("Zip() len = %d, want 3", len(got))
		}
		if got[0].First != 1 || got[0].Second != "a" {
			t.Errorf("got[0] = %v, want {1, a}", got[0])
		}
		if got[2].First != 3 || got[2].Second != "c" {
			t.Errorf("got[2] = %v, want {3, c}", got[2])
		}
	})
	t.Run("unequal length truncates", func(t *testing.T) {
		got := fp.Zip([]int{1, 2, 3}, []string{"a"})
		if len(got) != 1 {
			t.Fatalf("Zip() len = %d, want 1", len(got))
		}
		if got[0].First != 1 || got[0].Second != "a" {
			t.Errorf("got[0] = %v, want {1, a}", got[0])
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
