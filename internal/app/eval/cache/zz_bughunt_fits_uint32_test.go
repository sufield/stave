package cache

import "testing"

func TestBugHunt_FitsUint32(t *testing.T) {
	// Test standard values
	if !fitsUint32(0) {
		t.Errorf("fitsUint32(0) returned false, want true")
	}
	if !fitsUint32(100) {
		t.Errorf("fitsUint32(100) returned false, want true")
	}
}
