package cmd

import "testing"

func TestGroupedCommandAliasesExist(t *testing.T) {
	root := GetTestRootCmd()

	paths := [][]string{
		{"snapshot"},
		{"snapshot", "upcoming"},
		{"snapshot", "diff"},
		{"snapshot", "archive"},
		{"snapshot", "quality"},
		{"snapshot", "status"},
		{"snapshot", "risk"},
		{"ci"},
		{"ci", "baseline"},
		{"ci", "baseline", "save"},
		{"ci", "baseline", "check"},
		{"ci", "gate"},
		{"ci", "fix-loop"},
		{"ci", "fix"},
	}

	for _, path := range paths {
		if _, _, err := root.Find(path); err != nil {
			t.Fatalf("expected grouped command path %v to exist: %v", path, err)
		}
	}
}

func TestFlatLifecycleAndCICommandsAreNotTopLevel(t *testing.T) {
	root := GetTestRootCmd()

	flatTopLevel := [][]string{
		{"upcoming"},
		{"prune"},
		{"baseline"},
		{"gate"},
	}
	for _, path := range flatTopLevel {
		if _, _, err := root.Find(path); err == nil {
			t.Fatalf("expected top-level command %q to be removed", path[0])
		}
	}
}
