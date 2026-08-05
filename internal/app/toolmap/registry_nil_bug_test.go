package toolmap

import (
	"testing"
)

func TestRegistry_NilReceiverGuards(t *testing.T) {
	var r *Registry

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("Registry method panicked on nil receiver: %v", rec)
		}
	}()

	all := r.All()
	if len(all) != 0 {
		t.Errorf("expected empty tools for nil registry, got %v", all)
	}

	tool, ok := r.Tool("pacu")
	if ok || tool.Name != "" {
		t.Errorf("expected false, empty Tool for nil registry, got %v, %v", tool, ok)
	}

	res, err := Analyze(r, "chains", nil, "controls")
	if err == nil || res != nil {
		t.Errorf("expected error from Analyze with nil registry")
	}
}
