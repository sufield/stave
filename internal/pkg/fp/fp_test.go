package fp_test

import (
	"testing"

	"github.com/sufield/stave/internal/pkg/fp"
)

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

func TestSortedKeys(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		got := fp.SortedKeys(map[string]int(nil))
		if got != nil {
			t.Errorf("SortedKeys(nil) = %v, want nil", got)
		}
	})
	t.Run("returns sorted keys", func(t *testing.T) {
		got := fp.SortedKeys(map[string]int{"c": 3, "a": 1, "b": 2})
		want := []string{"a", "b", "c"}
		if len(got) != len(want) {
			t.Fatalf("SortedKeys() len = %d, want %d", len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
			}
		}
	})
	t.Run("integer keys", func(t *testing.T) {
		got := fp.SortedKeys(map[int]string{3: "c", 1: "a", 2: "b"})
		want := []int{1, 2, 3}
		if len(got) != len(want) {
			t.Fatalf("SortedKeys() len = %d, want %d", len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("index %d: got %d, want %d", i, got[i], want[i])
			}
		}
	})
}
