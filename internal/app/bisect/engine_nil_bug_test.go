package bisect

import (
	"context"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

func TestEngine_Run_NilEngineOrEvaluator(t *testing.T) {
	snaps := []asset.Snapshot{{CapturedAt: time.Now()}}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Engine.Run panicked: %v", r)
		}
	}()

	var e *Engine
	_, err := e.Run(context.Background(), snaps, ModeBisect, "CTL.1", "")
	if err == nil {
		t.Errorf("expected error for nil Engine, got nil")
	}

	e2 := &Engine{Evaluate: nil}
	_, err2 := e2.Run(context.Background(), snaps, ModeBisect, "CTL.1", "")
	if err2 == nil {
		t.Errorf("expected error for nil Evaluate function, got nil")
	}
}
