package sets

import (
	"strings"
	"testing"
)

func TestSet_AddContains(t *testing.T) {
	s := New[string]()
	s.Add("a")
	if !s.Contains("a") {
		t.Error("should contain 'a'")
	}
}

func TestSet_MissingKey(t *testing.T) {
	s := New[string]("x")
	if s.Contains("y") {
		t.Error("should not contain 'y'")
	}
}

func TestSet_Len(t *testing.T) {
	s := New("a", "b", "c")
	if s.Len() != 3 {
		t.Errorf("len = %d, want 3", s.Len())
	}
}

func TestSet_Slice(t *testing.T) {
	s := New("x", "y")
	sl := s.Slice()
	if len(sl) != 2 {
		t.Errorf("slice len = %d, want 2", len(sl))
	}
}

func TestSet_NewPrePopulated(t *testing.T) {
	s := New("a", "b")
	if !s.Contains("a") || !s.Contains("b") {
		t.Error("pre-populated items should be present")
	}
}

// TestSet_AddOnNilPanicsClearly pins that Add(item) on a nil Set
// surfaces a named panic. Without the guard, the runtime fired its
// generic "assignment to entry in nil map" and the call site was
// hard to find from the trace. The guard names the constructor.
func TestSet_AddOnNilPanicsClearly(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic from Add on nil Set, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected panic value to be a string, got %T", r)
		}
		if !strings.Contains(msg, "nil Set") || !strings.Contains(msg, "sets.New") {
			t.Errorf("panic message %q should mention nil Set and sets.New", msg)
		}
	}()
	var s Set[string] // zero-value: nil map under the hood
	s.Add("x")
}
