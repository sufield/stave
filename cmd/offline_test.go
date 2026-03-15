package cmd

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/domain/kernel"
)

// TestOfflineHelpSuffix_ProdCommands verifies that every production command
// that should display the offline guarantee does so, preventing drift.
func TestOfflineHelpSuffix_ProdCommands(t *testing.T) {
	root := GetRootCmd()

	// Command paths that must contain the offline help text in the prod binary.
	required := [][]string{
		{"apply"},
		{"ingest"},
		{"init"},
		{"ci"},
		{"ci", "baseline"},
		{"ci", "gate"},
		{"ci", "fix-loop"},
		{"snapshot"},
		{"snapshot", "diff"},
		{"snapshot", "upcoming"},
		{"snapshot", "prune"},
		{"snapshot", "archive"},
		{"snapshot", "quality"},
		{"snapshot", "hygiene"},
		{"explain"},
		{"validate"},
		{"diagnose"},
		{"verify"},
	}

	for _, path := range required {
		cmd, _, err := root.Find(path)
		if err != nil {
			t.Errorf("command path %v not found: %v", path, err)
			continue
		}
		long := cmd.Long
		if !strings.Contains(long, "Offline-only") {
			t.Errorf("%v: Long help does not contain 'Offline-only'", path)
		}
	}
}

// TestOfflineHelpSuffix_DevCommands verifies dev-only commands that should
// display the offline guarantee.
func TestOfflineHelpSuffix_DevCommands(t *testing.T) {
	root := GetDevRootCmd()

	required := [][]string{
		{"doctor"},
		{"bug-report"},
		{"controls"},
		{"capabilities"},
		{"security-audit"},
	}

	for _, path := range required {
		cmd, _, err := root.Find(path)
		if err != nil {
			t.Errorf("dev command path %v not found: %v", path, err)
			continue
		}
		long := cmd.Long
		if !strings.Contains(long, "Offline-only") {
			t.Errorf("%v: Long help does not contain 'Offline-only'", path)
		}
	}
}

// TestRequireOffline_PassesCleanEnv verifies the self-check passes without proxy vars.
func TestRequireOffline_PassesCleanEnv(t *testing.T) {
	app := &App{}
	app.Flags.RequireOffline = true

	// Ensure no proxy vars are set in this test process
	for _, env := range kernel.DefaultPolicy().ProxyEnvVars() {
		t.Setenv(env, "")
	}

	if err := app.checkRequireOffline(); err != nil {
		t.Errorf("checkRequireOffline() should pass in clean env, got: %v", err)
	}
}

// TestRequireOffline_FailsWithProxy verifies the self-check fails when proxy vars are set.
func TestRequireOffline_FailsWithProxy(t *testing.T) {
	app := &App{}
	app.Flags.RequireOffline = true

	t.Setenv("HTTP_PROXY", "http://proxy.example.com:8080")

	err := app.checkRequireOffline()
	if err == nil {
		t.Fatal("checkRequireOffline() should fail when HTTP_PROXY is set")
	}
	if !strings.Contains(err.Error(), "HTTP_PROXY") {
		t.Errorf("error should mention HTTP_PROXY, got: %v", err)
	}
}

// TestRequireOffline_SkippedWhenDisabled verifies no check when flag is off.
func TestRequireOffline_SkippedWhenDisabled(t *testing.T) {
	app := &App{}
	app.Flags.RequireOffline = false

	t.Setenv("HTTP_PROXY", "http://proxy.example.com:8080")

	if err := app.checkRequireOffline(); err != nil {
		t.Errorf("checkRequireOffline() should skip when disabled, got: %v", err)
	}
}
