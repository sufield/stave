package env

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/envvar"
)

func TestEnvList_TextOutput(t *testing.T) {
	root := getTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"env", "list"})
	if err := root.Execute(); err != nil {
		t.Fatalf("env list failed: %v", err)
	}

	out := buf.String()
	for _, v := range envvar.All() {
		if !strings.Contains(out, v.Name) {
			t.Errorf("expected %s in text output", v.Name)
		}
	}
	if !strings.Contains(out, "Configuration:") {
		t.Error("expected Configuration category header")
	}
	if !strings.Contains(out, "Debug:") {
		t.Error("expected Debug category header")
	}
}

func TestEnvList_JSONOutput(t *testing.T) {
	root := getTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"env", "list", "--format", "json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("env list --format json failed: %v", err)
	}

	var entries []struct {
		Name         string `json:"name"`
		Description  string `json:"description"`
		Category     string `json:"category"`
		Value        string `json:"value"`
		DefaultValue string `json:"default_value"`
	}
	if err := json.Unmarshal(buf.Bytes(), &entries); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
	}
	if len(entries) != 12 {
		t.Fatalf("expected 12 entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Name == "" || e.Description == "" || e.Category == "" {
			t.Errorf("entry has empty required field: %+v", e)
		}
	}
	// Verify default values are included for vars that have them.
	for _, e := range entries {
		if e.Name == envvar.MaxUnsafe.Name && e.DefaultValue != "168h" {
			t.Errorf("expected MaxUnsafe default_value=168h, got %q", e.DefaultValue)
		}
	}
}

func TestEnvList_ShowsCurrentValue(t *testing.T) {
	t.Setenv(envvar.Debug.Name, "1")

	root := getTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"env", "list", "--format", "text"})
	if err := root.Execute(); err != nil {
		t.Fatalf("env list failed: %v", err)
	}

	out := buf.String()
	// The line for STAVE_DEBUG should show the value "1" (not "(not set)").
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, envvar.Debug.Name) {
			if strings.Contains(line, "(not set)") {
				t.Fatal("expected STAVE_DEBUG value to be shown, got (not set)")
			}
			if !strings.Contains(line, "1") {
				t.Fatalf("expected value '1' for STAVE_DEBUG, got line: %s", line)
			}
			return
		}
	}
	t.Fatal("STAVE_DEBUG not found in output")
}

func TestEnvList_ShowsDefaultValue(t *testing.T) {
	root := getTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"env", "list", "--format", "text"})
	if err := root.Execute(); err != nil {
		t.Fatalf("env list failed: %v", err)
	}

	out := buf.String()
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, envvar.MaxUnsafe.Name) {
			if !strings.Contains(line, "168h") {
				t.Fatalf("expected effective default 168h for MaxUnsafe, got line: %s", line)
			}
			return
		}
	}
	t.Fatal("STAVE_MAX_UNSAFE not found in output")
}
