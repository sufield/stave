package bugreport

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func newTestRootCmd() *cobra.Command {
	root := &cobra.Command{}
	root.PersistentFlags().String("log-file", "", "")
	root.PersistentFlags().Bool("quiet", true, "")
	root.PersistentFlags().Bool("force", true, "")
	root.PersistentFlags().Bool("allow-symlink-output", false, "")
	return root
}

func TestCollectBugReportEnv_RedactsSensitive(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "super-secret")
	t.Setenv("STAVE_DEBUG", "1")

	entries := collectEnv()
	got := make(map[string]string, len(entries))
	for _, e := range entries {
		got[e.Key] = e.Value
	}

	if got["AWS_REGION"] != "us-east-1" {
		t.Fatalf("AWS_REGION = %q, want us-east-1", got["AWS_REGION"])
	}
	if got["STAVE_DEBUG"] != "1" {
		t.Fatalf("STAVE_DEBUG = %q, want 1", got["STAVE_DEBUG"])
	}
	if got["AWS_SECRET_ACCESS_KEY"] != "[SANITIZED]" {
		t.Fatalf("AWS_SECRET_ACCESS_KEY = %q, want [SANITIZED]", got["AWS_SECRET_ACCESS_KEY"])
	}
}

func TestRedactSensitiveBlob(t *testing.T) {
	in := []byte(strings.Join([]string{
		"aws_secret_access_key: super-secret",
		"api_token=token-value",
		"access_key: AKIAABCDEFGHIJKLMNOP",
		"url: https://user:pass@example.com/path",
	}, "\n"))

	out := string(redactSensitiveBlob(in))
	if strings.Contains(out, "super-secret") || strings.Contains(out, "token-value") || strings.Contains(out, "AKIAABCDEFGHIJKLMNOP") || strings.Contains(out, "user:pass@") {
		t.Fatalf("sanitization failed, got:\n%s", out)
	}
	if !strings.Contains(out, "aws_secret_access_key: [SANITIZED]") {
		t.Fatalf("expected key/value sanitization, got:\n%s", out)
	}
}

func TestRunBugReport_CreatesBundle(t *testing.T) {
	tmpDir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	require := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	require(os.Chdir(tmpDir))
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	// Minimal project config discoverable by findNearestFile(projectConfigFile).
	require(os.WriteFile("stave.yaml", []byte("name: demo\napi_token: secret-value\n"), 0o600))
	require(os.WriteFile("stave.log", []byte("line1\nline2\nline3\n"), 0o600))
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret-from-env")
	t.Setenv("AWS_REGION", "us-west-2")

	// Save and restore package-level vars used by runReport.
	oldOut := reportOut
	oldTail := tailLines
	oldCfg := includeConfig
	t.Cleanup(func() {
		reportOut = oldOut
		tailLines = oldTail
		includeConfig = oldCfg
	})

	bundlePath := filepath.Join(tmpDir, "diag.zip")
	reportOut = bundlePath
	tailLines = 2
	includeConfig = true

	// Build a root command with the persistent flags that cmdutil helpers read.
	root := newTestRootCmd()
	cmd := &cobra.Command{}
	root.AddCommand(cmd)
	cmd.SetOut(io.Discard)

	require(runReport(cmd, nil))

	zr, err := zip.OpenReader(bundlePath)
	if err != nil {
		t.Fatalf("open bundle zip: %v", err)
	}
	defer zr.Close()

	files := make(map[string][]byte, len(zr.File))
	for _, f := range zr.File {
		rc, openErr := f.Open()
		if openErr != nil {
			t.Fatalf("open zip entry %s: %v", f.Name, openErr)
		}
		data, readErr := io.ReadAll(rc)
		_ = rc.Close()
		if readErr != nil {
			t.Fatalf("read zip entry %s: %v", f.Name, readErr)
		}
		files[f.Name] = data
	}

	required := []string{
		"doctor.json",
		"build_info.json",
		"env.json",
		"args.json",
		"manifest.json",
		"config/stave.yaml",
		"logs/stave.log.tail.txt",
	}
	for _, name := range required {
		if _, ok := files[name]; !ok {
			t.Fatalf("bundle missing %s", name)
		}
	}

	// Ensure config and env are sanitized.
	if bytes.Contains(files["config/stave.yaml"], []byte("secret-value")) {
		t.Fatal("config should be sanitized")
	}

	var envEntries []envEntry
	if err := json.Unmarshal(files["env.json"], &envEntries); err != nil {
		t.Fatalf("unmarshal env.json: %v", err)
	}
	var envSecretValue string
	for _, e := range envEntries {
		if e.Key == "AWS_SECRET_ACCESS_KEY" {
			envSecretValue = e.Value
			break
		}
	}
	if envSecretValue != "[SANITIZED]" {
		t.Fatalf("AWS_SECRET_ACCESS_KEY in env.json = %q, want [SANITIZED]", envSecretValue)
	}

	var argsEntries []string
	if err := json.Unmarshal(files["args.json"], &argsEntries); err != nil {
		t.Fatalf("unmarshal args.json: %v", err)
	}
	if len(argsEntries) == 0 {
		t.Fatal("args.json should not be empty")
	}

	// Tail should include only the last two lines.
	logTail := string(files["logs/stave.log.tail.txt"])
	if strings.Contains(logTail, "line1") || !strings.Contains(logTail, "line2") || !strings.Contains(logTail, "line3") {
		t.Fatalf("unexpected log tail content: %q", logTail)
	}
}
