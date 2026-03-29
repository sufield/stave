package config

import (
	"bytes"
	"strings"
	"testing"

	appconfig "github.com/sufield/stave/internal/app/config"
)

func TestConfigFileLine_WithPath(t *testing.T) {
	got := configFileLine("/home/user/stave.yaml")
	if !strings.Contains(got, "/home/user/stave.yaml") {
		t.Fatalf("expected path in output, got: %q", got)
	}
	if !strings.HasPrefix(got, "Config file:") {
		t.Fatalf("expected 'Config file:' prefix, got: %q", got)
	}
}

func TestConfigFileLine_Empty(t *testing.T) {
	got := configFileLine("")
	if !strings.Contains(got, "none found") {
		t.Fatalf("expected 'none found' for empty path, got: %q", got)
	}
}

func TestSortedKeys(t *testing.T) {
	m := map[string]int{"z": 1, "a": 2, "m": 3}
	got := sortedKeys(m)
	if len(got) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(got))
	}
	if got[0] != "a" || got[1] != "m" || got[2] != "z" {
		t.Fatalf("expected sorted order, got: %v", got)
	}
}

func TestSortedKeys_Empty(t *testing.T) {
	m := map[string]int{}
	got := sortedKeys(m)
	if len(got) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(got))
	}
}

func TestWriteLines(t *testing.T) {
	var buf bytes.Buffer
	err := writeLines(&buf, "line1", "line2", "line3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "line1\n") {
		t.Fatalf("expected line1, got: %s", out)
	}
	if !strings.Contains(out, "line3\n") {
		t.Fatalf("expected line3, got: %s", out)
	}
}

func TestBuildShowOutput(t *testing.T) {
	eval := appconfig.NewEvaluator(nil, "", nil, "")
	out := buildShowOutput(eval)
	if out.MaxUnsafeDuration.Value == "" {
		t.Fatal("expected non-empty max_unsafe default")
	}
	if out.MaxUnsafeDuration.Source == "" {
		t.Fatal("expected non-empty max_unsafe source")
	}
}

func TestShowPresenter_RenderText(t *testing.T) {
	eval := appconfig.NewEvaluator(nil, "", nil, "")
	out := buildShowOutput(eval)

	var buf bytes.Buffer
	p := &ShowPresenter{Stdout: &buf}
	err := p.Render(out, false)
	if err != nil {
		t.Fatalf("Render text error: %v", err)
	}
	rendered := buf.String()
	if !strings.Contains(rendered, "Effective Configuration") {
		t.Fatalf("expected 'Effective Configuration' header, got: %s", rendered)
	}
	if !strings.Contains(rendered, "max_unsafe:") {
		t.Fatalf("expected max_unsafe, got: %s", rendered)
	}
}

func TestShowPresenter_RenderJSON(t *testing.T) {
	eval := appconfig.NewEvaluator(nil, "", nil, "")
	out := buildShowOutput(eval)

	var buf bytes.Buffer
	p := &ShowPresenter{Stdout: &buf}
	err := p.Render(out, true)
	if err != nil {
		t.Fatalf("Render JSON error: %v", err)
	}
	rendered := buf.String()
	if !strings.Contains(rendered, "max_unsafe") {
		t.Fatalf("expected JSON key 'max_unsafe', got: %s", rendered)
	}
}

func TestValueResult_Structure(t *testing.T) {
	vr := ValueResult{
		Key:    "max_unsafe",
		Value:  "168h",
		Source: "default",
	}
	if vr.Key != "max_unsafe" {
		t.Fatalf("Key = %q", vr.Key)
	}
}
