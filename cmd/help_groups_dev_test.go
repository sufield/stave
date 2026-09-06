package cmd

import "testing"

func TestPromotedCommandsRegistered(t *testing.T) {
	t.Parallel()
	app, err := NewApp()
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	root := app.Root

	promoted := []string{
		"doctor",
		"graph",
		"alias",
		"capabilities",
		"version",
		"lint",
		"controls",
	}

	for _, use := range promoted {
		cmd, _, err := root.Find([]string{use})
		if err != nil || cmd == nil {
			t.Fatalf("expected command %q to be registered in production tree", use)
		}
	}

	// trace is a subcommand of diagnose; schemas and path are
	// subcommands of contract and graph respectively.
	subcommands := map[string][]string{
		"diagnose": {"trace"},
		"contract": {"schemas"},
		"graph":    {"path"},
		"controls": {"lint", "fmt"},
	}
	for parent, subs := range subcommands {
		for _, sub := range subs {
			cmd, _, err := root.Find([]string{parent, sub})
			if err != nil || cmd == nil {
				t.Fatalf("expected command %q to be registered under %s", sub, parent)
			}
		}
	}
}
