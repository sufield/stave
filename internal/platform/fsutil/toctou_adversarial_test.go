package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSafeMkdirAll_TOCTOU_WithHook injects a symlink swap between
// the Lstat check and the Mkdir call using the testHookAfterLstat
// variable. This deterministically tests whether the TOCTOU window
// is closed — without relying on race timing.
func TestSafeMkdirAll_TOCTOU_WithHook(t *testing.T) {
	tmpDir := t.TempDir()

	attackerTarget := filepath.Join(tmpDir, "attacker")
	if err := os.Mkdir(attackerTarget, 0o755); err != nil {
		t.Fatal(err)
	}

	// The hook will fire when SafeMkdirAll is about to create "subdir"
	// under legitPath. We swap legitPath for a symlink to attackerTarget.
	legitPath := filepath.Join(tmpDir, "legit")

	testHookAfterLstat = func(component string) {
		if filepath.Base(component) == "subdir" {
			// Swap the parent directory for a symlink right before Mkdir.
			// This simulates an attacker acting in the TOCTOU window.
			_ = os.Remove(legitPath)
			_ = os.Symlink(attackerTarget, legitPath)
		}
	}
	defer func() { testHookAfterLstat = nil }()

	targetPath := filepath.Join(legitPath, "subdir")

	err := SafeMkdirAll(targetPath, WriteOptions{Perm: 0o755})

	// Check if the attack succeeded — directory created at attacker target.
	redirectedPath := filepath.Join(attackerTarget, "subdir")
	if _, statErr := os.Stat(redirectedPath); statErr == nil {
		t.Error(
			"TOCTOU VULNERABILITY: directory created at attacker-controlled " +
				"location after symlink swap in the race window")
	}

	if err != nil {
		t.Logf("FIXED: SafeMkdirAll detected symlink swap and returned error: %v", err)
	}
}

// TestSafeMkdirAll_TOCTOU_HookDoesNotBreakNormalPath verifies that
// the re-check after the hook doesn't break normal (non-attacked) paths.
func TestSafeMkdirAll_TOCTOU_HookDoesNotBreakNormalPath(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "normal", "subdir")

	err := SafeMkdirAll(targetPath, WriteOptions{Perm: 0o755})
	if err != nil {
		t.Fatalf("normal path creation failed: %v", err)
	}

	info, err := os.Stat(targetPath)
	if err != nil || !info.IsDir() {
		t.Error("normal directory not created correctly")
	}
}
