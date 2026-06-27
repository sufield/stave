package observations

import (
	"context"
	"testing"
)

func TestBugHunt_DaemonContext(t *testing.T) {
	// 1. Verify isDaemonContext is false for background context
	bgCtx := context.Background()
	if isDaemonContext(bgCtx) {
		t.Error("expected default context not to be daemon context")
	}

	// 2. Verify tagging context with DaemonContext makes isDaemonContext true
	daemonCtx := DaemonContext(bgCtx)
	if !isDaemonContext(daemonCtx) {
		t.Error("expected context tagged with DaemonContext to be detected as daemon context")
	}
}
