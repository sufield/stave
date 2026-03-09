package cmd

import (
	"os"
	"testing"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
)

func chdirForConfigTest(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}

func TestConfigKeyCompletions_IncludeServiceTopLevelKeys(t *testing.T) {
	temp := t.TempDir()
	chdirForConfigTest(t, temp)

	keys := projconfig.ConfigKeyCompletions()
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate completion key %q", key)
		}
		seen[key] = struct{}{}
	}

	for _, key := range projconfig.ConfigKeyService.TopLevelKeys() {
		if _, ok := seen[key]; !ok {
			t.Fatalf("missing top-level key completion %q", key)
		}
	}

	requiredTierKeys := []string{
		"snapshot_retention_tiers." + projconfig.DefaultRetentionTier,
		"snapshot_retention_tiers." + projconfig.DefaultRetentionTier + ".older_than",
		"snapshot_retention_tiers." + projconfig.DefaultRetentionTier + ".keep_min",
	}
	for _, key := range requiredTierKeys {
		if _, ok := seen[key]; !ok {
			t.Fatalf("missing tier completion key %q", key)
		}
	}
}
