package cmd

import "testing"

func TestPromotedCommandsRegistered(t *testing.T) {
	root := NewApp().Root

	promoted := []string{
		"doctor",
		"bug-report",
		"graph",
		"docs",
		"alias",
		"schemas",
		"capabilities",
		"version",
		"trace",
		"prompt",
		"lint",
		"fmt",
		"controls",
		"packs",
	}

	for _, use := range promoted {
		cmd, _, err := root.Find([]string{use})
		if err != nil || cmd == nil {
			t.Fatalf("expected command %q to be registered in production tree", use)
		}
	}
}
