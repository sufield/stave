package cmd

import "testing"

func TestGroupedCommandAliasesExist_Dev(t *testing.T) {
	root := getDevRootCmd()

	paths := [][]string{
		{"snapshot"},
	}

	for _, path := range paths {
		if _, _, err := root.Find(path); err != nil {
			t.Fatalf("expected dev command path %v to exist: %v", path, err)
		}
	}
}
