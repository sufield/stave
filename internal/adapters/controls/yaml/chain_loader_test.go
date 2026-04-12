package yaml

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadChains(t *testing.T) {
	t.Run("loads valid chains", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "test.yaml", `
id: test_chain
description: test
controls:
  - CTL.A.001
  - CTL.B.001
escalation_threshold: 2
compound_severity: high
`)
		chains, err := LoadChains(dir)
		if err != nil {
			t.Fatalf("LoadChains: %v", err)
		}
		if len(chains) != 1 {
			t.Fatalf("expected 1 chain, got %d", len(chains))
		}
		if chains[0].ID != "test_chain" {
			t.Errorf("ID = %q, want test_chain", chains[0].ID)
		}
		if len(chains[0].ControlIDs) != 2 {
			t.Errorf("controls = %d, want 2", len(chains[0].ControlIDs))
		}
	})

	t.Run("missing directory returns nil", func(t *testing.T) {
		chains, err := LoadChains("/nonexistent/path")
		if err != nil {
			t.Fatalf("expected nil error for missing dir, got: %v", err)
		}
		if chains != nil {
			t.Errorf("expected nil chains, got %d", len(chains))
		}
	})

	t.Run("invalid chain fails validation", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "bad.yaml", `
id: bad
controls:
  - CTL.A.001
escalation_threshold: 1
`)
		_, err := LoadChains(dir)
		if err == nil {
			t.Fatal("expected validation error for chain with 1 control")
		}
	})

	t.Run("sorted by ID", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "z_chain.yaml", `
id: z_chain
controls: [CTL.A.001, CTL.B.001]
escalation_threshold: 1
`)
		writeFile(t, dir, "a_chain.yaml", `
id: a_chain
controls: [CTL.C.001, CTL.D.001]
escalation_threshold: 1
`)
		chains, err := LoadChains(dir)
		if err != nil {
			t.Fatalf("LoadChains: %v", err)
		}
		if len(chains) != 2 || chains[0].ID != "a_chain" {
			t.Errorf("expected sorted [a_chain, z_chain], got %v", chains)
		}
	})

	t.Run("skips non-yaml files", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "readme.md", "# not a chain")
		writeFile(t, dir, "valid.yaml", `
id: valid
controls: [CTL.A.001, CTL.B.001]
escalation_threshold: 1
`)
		chains, err := LoadChains(dir)
		if err != nil {
			t.Fatalf("LoadChains: %v", err)
		}
		if len(chains) != 1 {
			t.Errorf("expected 1 chain (skip .md), got %d", len(chains))
		}
	})
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
