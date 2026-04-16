package sets

import "testing"

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
