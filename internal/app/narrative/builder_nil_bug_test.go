package narrative

import (
	"testing"
)

func TestBuildPlaybook_NilInputHandledSafely(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("BuildPlaybook panicked on nil input: %v", rec)
		}
	}()

	pb := BuildPlaybook(nil)
	if pb.FindingID != "" || pb.ControlID != "" {
		t.Errorf("expected empty Playbook for nil input")
	}
}
