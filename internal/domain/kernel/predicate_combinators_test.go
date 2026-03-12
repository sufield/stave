package kernel

import "testing"

func TestAnd_EmptyIsTrue(t *testing.T) {
	p := And[int]()
	if !p(0) {
		t.Error("And() with no predicates should return true")
	}
}

func TestAnd_Single(t *testing.T) {
	called := false
	inner := Predicate[int](func(v int) bool { called = true; return v > 0 })
	p := And(inner)
	if p(1) != true || !called {
		t.Error("And with single predicate should delegate directly")
	}
}

func TestAnd_ShortCircuits(t *testing.T) {
	p := And(
		func(v int) bool { return v > 0 },
		func(v int) bool { return v < 10 },
	)
	if !p(5) {
		t.Error("expected true for 5")
	}
	if p(0) {
		t.Error("expected false for 0")
	}
}

func TestOr_EmptyIsFalse(t *testing.T) {
	p := Or[int]()
	if p(0) {
		t.Error("Or() with no predicates should return false")
	}
}

func TestOr_Single(t *testing.T) {
	inner := Predicate[int](func(v int) bool { return v > 0 })
	p := Or(inner)
	if p(-1) {
		t.Error("expected false for -1")
	}
	if !p(1) {
		t.Error("expected true for 1")
	}
}

func TestOr_ShortCircuits(t *testing.T) {
	p := Or(
		func(v int) bool { return v == 1 },
		func(v int) bool { return v == 2 },
	)
	if !p(2) {
		t.Error("expected true for 2")
	}
	if p(3) {
		t.Error("expected false for 3")
	}
}

func TestNot(t *testing.T) {
	p := Not(func(v int) bool { return v > 0 })
	if !p(-1) {
		t.Error("expected true for -1")
	}
	if p(1) {
		t.Error("expected false for 1")
	}
}

func TestNot_NilIsTrue(t *testing.T) {
	p := Not[int](nil)
	if !p(0) {
		t.Error("Not(nil) should return true")
	}
}

func TestAlwaysTrue(t *testing.T) {
	if !AlwaysTrue[int]()(42) {
		t.Error("AlwaysTrue should return true")
	}
}

func TestAlwaysFalse(t *testing.T) {
	if AlwaysFalse[int]()(42) {
		t.Error("AlwaysFalse should return false")
	}
}

func TestComposition(t *testing.T) {
	p := And(AlwaysTrue[int](), Not(AlwaysFalse[int]()))
	if !p(42) {
		t.Error("composed predicate should return true")
	}
}
