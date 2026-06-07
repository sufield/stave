package stave

import (
	"strings"
	"testing"
	"time"
)

func TestResolveCrosswalk_RejectsUnknownFramework(t *testing.T) {
	_, err := ResolveCrosswalk([]byte("version: 1\nchecks: {}\n"), []string{"definitely_not_a_framework"}, nil, time.Unix(0, 0).UTC())
	if err == nil {
		t.Fatal("expected an error for an unknown framework")
	}
	if !strings.Contains(err.Error(), "invalid framework") {
		t.Errorf("error should mention %q, got: %q", "invalid framework", err.Error())
	}
}

func TestResolveCrosswalk_EmptyFrameworksResolves(t *testing.T) {
	// No framework filter + an empty checks doc: the resolver should
	// succeed and return JSON bytes (the contract cmd/inspect/compliance
	// writes to stdout).
	out, err := ResolveCrosswalk([]byte("version: 1\nchecks: {}\n"), nil, nil, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected non-empty resolution JSON")
	}
}
