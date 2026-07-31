package coverage

import (
	"testing"
)

func TestNavigatorLayer_NilReport(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NavigatorLayer panicked on nil report: %v", r)
		}
	}()

	res := NavigatorLayer(nil)
	if res != nil {
		t.Errorf("expected nil result for nil report, got %v", res)
	}
}
