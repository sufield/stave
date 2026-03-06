package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/testutil"
)

func TestMinimumS3IngestIAMActions_MatchesManifest(t *testing.T) {
	got := MinimumS3IngestIAMActions()
	if len(got) == 0 {
		t.Fatal("MinimumS3IngestIAMActions returned empty list")
	}

	manifestSet := map[string]bool{}
	for _, entry := range S3IngestIAMManifest {
		manifestSet[entry.Action] = true
	}
	if len(got) != len(manifestSet) {
		t.Fatalf("action count mismatch: got=%d manifest=%d", len(got), len(manifestSet))
	}
	for _, action := range got {
		if !manifestSet[action] {
			t.Fatalf("unexpected action in output: %s", action)
		}
	}
}

func TestIAMMinimumDocs_MatchesManifest(t *testing.T) {
	root := findRepoRoot(t)
	docPath := filepath.Join(root, "docs", "security", "iam-minimum-s3-ingest.md")
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read iam docs: %v", err)
	}
	content := string(data)

	manifestActions := MinimumS3IngestIAMActions()
	for _, entry := range S3IngestIAMManifest {
		if !strings.Contains(content, "`"+entry.Operation+"`") {
			t.Fatalf("docs missing operation %q", entry.Operation)
		}
		if !strings.Contains(content, "`"+entry.Action+"`") {
			t.Fatalf("docs missing action %q", entry.Action)
		}
	}

	re := regexp.MustCompile(`s3:[A-Za-z0-9]+`)
	matches := re.FindAllString(content, -1)
	for _, action := range matches {
		if !slices.Contains(manifestActions, action) {
			t.Fatalf("docs contain unsupported IAM action %q not in manifest", action)
		}
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	return testutil.RepoRoot(t)
}
