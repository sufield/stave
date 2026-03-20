package domain

import (
	"testing"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func TestPredicateCombinators(t *testing.T) {
	isEven := func(v int) bool { return v%2 == 0 }
	isPositive := func(v int) bool { return v > 0 }

	if got := kernel.And[int](isEven, isPositive)(2); !got {
		t.Fatal("expected And to match for positive even value")
	}
	if got := kernel.And[int](isEven, isPositive)(-2); got {
		t.Fatal("expected And to fail when one predicate fails")
	}
	if got := kernel.Or[int](isEven, isPositive)(-3); got {
		t.Fatal("expected Or to fail when all predicates fail")
	}
	if got := kernel.Or[int](isEven, isPositive)(3); !got {
		t.Fatal("expected Or to match when at least one predicate matches")
	}
	if got := kernel.Not[int](isEven)(3); !got {
		t.Fatal("expected Not to invert predicate result")
	}
}
