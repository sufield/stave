package metadata

import (
	"testing"

	"github.com/sufield/stave/internal/env"
)

func TestDocsRef_Default(t *testing.T) {
	t.Setenv(env.DocsURL.Name, "")
	got := DocsRef("troubleshooting")
	if got != "run 'stave docs search troubleshooting'" {
		t.Errorf("DocsRef = %q", got)
	}
}

func TestDocsRef_EmptyTopic(t *testing.T) {
	t.Setenv(env.DocsURL.Name, "")
	got := DocsRef("")
	if got != "run 'stave docs search troubleshooting'" {
		t.Errorf("DocsRef('') = %q", got)
	}
}

func TestDocsRef_WithEnvURL(t *testing.T) {
	t.Setenv(env.DocsURL.Name, "https://docs.example.com")
	got := DocsRef("setup")
	if got != "https://docs.example.com#setup" {
		t.Errorf("DocsRef = %q", got)
	}
}

func TestIssuesRef(t *testing.T) {
	// Just verify it doesn't panic and returns a string
	got := IssuesRef()
	_ = got
}

func TestCommand_Empty(t *testing.T) {
	if got := Command(""); got != CLIName {
		t.Errorf("Command('') = %q, want %q", got, CLIName)
	}
}

func TestCommand_WithSubcommand(t *testing.T) {
	if got := Command("apply"); got != "stave apply" {
		t.Errorf("Command('apply') = %q", got)
	}
}
