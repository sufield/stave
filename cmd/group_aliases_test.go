package cmd

import "testing"

func TestGroupedCommandAliasesExist(t *testing.T) {
	root := GetRootCmd()

	paths := [][]string{
		{"snapshot"},
		{"snapshot", "upcoming"},
		{"snapshot", "diff"},
		{"snapshot", "prune"},
		{"snapshot", "archive"},
		{"snapshot", "quality"},
		{"snapshot", "hygiene"},
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

func TestGroupedCommandAliasesExist_Dev(t *testing.T) {
	root := GetDevRootCmd()

	paths := [][]string{
		{"docs"},
		{"docs", "search"},
		{"docs", "open"},
	}

	for _, path := range paths {
		if _, _, err := root.Find(path); err != nil {
			t.Fatalf("expected dev command path %v to exist: %v", path, err)
		}
	}
}

func TestFlatLifecycleAndCICommandsAreNotTopLevel(t *testing.T) {
	root := GetRootCmd()

	flatTopLevel := [][]string{
		{"upcoming"},
		{"diff"},
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
