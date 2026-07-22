package stave_test

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/pkg/stave"
)

func TestSignSnapshot_RejectsNonObservation(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	assessment := `{"schema_version":"out.v0.1","findings":[{"id":"F1"}]}`
	_, err = stave.SignSnapshot([]byte(assessment), priv, "", "test", time.Now())
	if err == nil {
		t.Fatal("expected error signing non-observation file")
	}
	if !strings.Contains(err.Error(), "no assets array") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSignSnapshot_AcceptsObservation(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	obs := `{"schema_version":"obs.v0.1","captured_at":"2026-01-01T00:00:00Z","source":"test","assets":[{"id":"arn:aws:s3:::b","type":"aws_s3_bucket","properties":{}}]}`
	out, err := stave.SignSnapshot([]byte(obs), priv, "", "test", time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected non-empty output")
	}
}
