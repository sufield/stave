package cmd

import "testing"

func TestPromotedCommandsRegistered(t *testing.T) {
	root := NewApp().Root

	promoted := []string{
		"doctor",
		"graph",
		"alias",
		"schemas",
		"capabilities",
		"version",
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

	// trace and prompt are subcommands of diagnose.
	for _, sub := range []string{"trace", "prompt"} {
		cmd, _, err := root.Find([]string{"diagnose", sub})
		if err != nil || cmd == nil {
			t.Fatalf("expected command %q to be registered under diagnose", sub)
		}
	}
}
