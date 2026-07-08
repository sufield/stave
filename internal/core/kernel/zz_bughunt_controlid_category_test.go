package kernel

import "testing"

func TestBugHunt_ControlID_Category_NoCategory(t *testing.T) {
	id := ControlID("CTL.S3.001")
	got := id.Category()
	want := ""
	if got != want {
		t.Errorf("ControlID(%q).Category() = %q, want %q", id, got, want)
	}
}
