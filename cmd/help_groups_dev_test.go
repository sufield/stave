//go:build stavedev

package cmd

import "testing"

func TestDevHelpGroupsAssigned(t *testing.T) {
	root := GetDevRootCmd()

	devChecks := map[string]string{
		"doctor":       groupDevTools,
		"bug-report":   groupDevTools,
		"prompt":       groupDevTools,
		"trace":        groupDevTools,
		"controls":     groupDevTools,
		"packs":        groupDevTools,
		"graph":        groupDevTools,
		"lint":         groupDevTools,
		"fmt":          groupDevTools,
		"docs":         groupDevTools,
		"alias":        groupDevTools,
		"schemas":      groupDevTools,
		"capabilities": groupDevTools,
		"version":      groupDevTools,
	}

	for use, wantGroup := range devChecks {
		cmd, _, err := root.Find([]string{use})
		if err != nil {
			t.Fatalf("expected dev command %q: %v", use, err)
		}
		if cmd.GroupID != wantGroup {
			t.Fatalf("dev command %q group=%q, want %q", use, cmd.GroupID, wantGroup)
		}
	}
}
