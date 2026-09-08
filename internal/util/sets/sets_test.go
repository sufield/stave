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

func TestSet_NewPrePopulated(t *testing.T) {
	s := New("a", "b")
	if !s.Contains("a") || !s.Contains("b") {
		t.Error("pre-populated items should be present")
	}
}

// TestSet_NilReadsAreTotal pins the documented contract: read-only
// methods on a nil Set return zero values rather than panicking.
// Add still panics (writes need a map). Together these match the
// natural semantics of Go's nil-map reads vs writes.
func TestSet_NilReadsAreTotal(t *testing.T) {
	var s Set[string]
	if s.Contains("anything") {
		t.Error("Contains on nil Set must return false")
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
