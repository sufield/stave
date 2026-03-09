package initcmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitProfileAWSS3AddsProfileStructure(t *testing.T) {
	projectDir := filepath.Join(t.TempDir(), "stave-project")
	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"init", "--dir", projectDir, "--profile", "aws-s3"})
	if err := root.Execute(); err != nil {
		t.Fatalf("init command failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(projectDir, "snapshots/raw/aws-s3/README.md")); err != nil {
		t.Fatalf("expected aws-s3 profile README: %v", err)
	}
	readme, err := os.ReadFile(filepath.Join(projectDir, "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	if !strings.Contains(string(readme), "--input ./snapshots/raw/aws-s3") {
		t.Fatalf("expected profile-specific README command, got: %s", string(readme))
	}
}

func TestInitWithGitHubActionsCreatesWorkflow(t *testing.T) {
	projectDir := filepath.Join(t.TempDir(), "stave-project")
	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"init", "--dir", projectDir, "--with-github-actions"})
	if err := root.Execute(); err != nil {
		t.Fatalf("init command failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(projectDir, ".github/workflows/stave.yml")); err != nil {
		t.Fatalf("expected GitHub Actions workflow: %v", err)
	}
	workflowData, err := os.ReadFile(filepath.Join(projectDir, ".github/workflows/stave.yml"))
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	workflow := string(workflowData)
	mustContain := []string{
		"go install github.com/sufield/stave/cmd/stave@latest",
		"schedule:",
		"cron: \"0 2 * * *\"",
		"stave validate",
		"stave snapshot quality",
		"stave apply",
		"stave ci gate",
		"ci_failure_policy:",
		"stave snapshot upcoming",
		"SNAPSHOT_FILE=observations/$(date -u +'%Y-%m-%dT00:00:00Z').json",
		"actions/upload-artifact@v4",
	}
	for _, needle := range mustContain {
		if !strings.Contains(workflow, needle) {
			t.Fatalf("workflow missing required snippet %q", needle)
		}
	}
}

func TestInitRejectsUnsupportedProfile(t *testing.T) {
	projectDir := filepath.Join(t.TempDir(), "stave-project")
	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"init", "--dir", projectDir, "--profile", "unknown"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected init to fail for unsupported profile")
	}
	if !strings.Contains(err.Error(), "unsupported --profile") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitWithHourlyCaptureCadence(t *testing.T) {
	projectDir := filepath.Join(t.TempDir(), "stave-project")
	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"init", "--dir", projectDir, "--with-github-actions", "--capture-cadence", "hourly"})
	if err := root.Execute(); err != nil {
		t.Fatalf("init command failed: %v", err)
	}

	configData, err := os.ReadFile(filepath.Join(projectDir, projectConfigFile))
	if err != nil {
		t.Fatalf("read %s: %v", projectConfigFile, err)
	}
	config := string(configData)
	if !strings.Contains(config, "capture_cadence: hourly") {
		t.Fatalf("expected hourly cadence in config, got: %s", config)
	}
	if !strings.Contains(config, "snapshot_filename_template: YYYY-MM-DDTHH0000Z.json") {
		t.Fatalf("expected hourly naming template in config, got: %s", config)
	}

	workflowData, err := os.ReadFile(filepath.Join(projectDir, ".github/workflows/stave.yml"))
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	workflow := string(workflowData)
	if !strings.Contains(workflow, "cron: \"0 * * * *\"") {
		t.Fatalf("expected hourly cron in workflow, got: %s", workflow)
	}
	if !strings.Contains(workflow, "SNAPSHOT_FILE=observations/$(date -u +'%Y-%m-%dT%H:00:00Z').json") {
		t.Fatalf("expected hourly snapshot filename convention in workflow, got: %s", workflow)
	}
}

func TestInitRejectsUnsupportedCaptureCadence(t *testing.T) {
	projectDir := filepath.Join(t.TempDir(), "stave-project")
	root := GetRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"init", "--dir", projectDir, "--capture-cadence", "weekly"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected init to fail for unsupported capture cadence")
	}
	if !strings.Contains(err.Error(), "unsupported --capture-cadence") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPromptInitializeGit_DefaultYes(t *testing.T) {
	var out bytes.Buffer
	ok, err := promptInitializeGit("/tmp/stave", strings.NewReader("\n"), &out)
	if err != nil {
		t.Fatalf("promptInitializeGit error: %v", err)
	}
	if !ok {
		t.Fatal("expected default answer to accept git init")
	}
	if !strings.Contains(out.String(), "Initialize now? [Y/n]:") {
		t.Fatalf("expected prompt text, got: %q", out.String())
	}
}

func TestPromptInitializeGit_No(t *testing.T) {
	var out bytes.Buffer
	ok, err := promptInitializeGit("/tmp/stave", strings.NewReader("n\n"), &out)
	if err != nil {
		t.Fatalf("promptInitializeGit error: %v", err)
	}
	if ok {
		t.Fatal("expected \"n\" to decline git init")
	}
}
