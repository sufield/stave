package evaluation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestEvaluationMetadata_ToMap_Golden(t *testing.T) {
	meta := Metadata{
		ContextName: "prod-check",
		ControlSource: ControlSourceInfo{
			Source:       "packs",
			EnabledPacks: []string{"cis-aws-v1"},
		},
		ResolvedPaths: ResolvedPaths{
			Controls:     "/tmp/ctl.yaml",
			Observations: "/tmp/obs.json",
		},
		Git: &GitInfo{
			RepoRoot: "/work/stave",
			Dirty:    true,
		},
	}

	got := meta.ToMap()

	goldenPath := filepath.Join("testdata", "evaluation_metadata.golden.json")
	bytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("failed to read golden file: %v", err)
	}

	var want map[string]any
	if err := json.Unmarshal(bytes, &want); err != nil {
		t.Fatalf("failed to unmarshal golden file: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("ToMap() logic drift detected\ngot:  %#v\nwant: %#v", got, want)
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		t.Logf("actual JSON output:\n%s", string(gotJSON))
	}
}
