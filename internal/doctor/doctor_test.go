package doctor

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRun_UsesConfiguredChecksAndHasFail(t *testing.T) {
	reg := NewRegistry(
		func(*Context) Check { return Check{Name: "ok", Status: StatusPass} },
		func(*Context) Check { return Check{} }, // skipped
		func(*Context) Check { return Check{Name: "bad", Status: StatusFail} },
	)

	checks, ok := RunWithRegistry(nil, reg)
	if ok {
		t.Fatal("expected success=false when FAIL present")
	}
	if len(checks) != 2 {
		t.Fatalf("check count = %d, want 2", len(checks))
	}
}

func TestWithDefaults(t *testing.T) {
	ctx := NewContext()
	if ctx.LookPathFn == nil || ctx.GetenvFn == nil {
		t.Fatal("expected default function pointers")
	}
	if ctx.Goos == "" || ctx.Goarch == "" || ctx.GoVersion == "" {
		t.Fatalf("expected runtime defaults, got goos=%q goarch=%q goversion=%q", ctx.Goos, ctx.Goarch, ctx.GoVersion)
	}
}

func TestCheckClipboard(t *testing.T) {
	pass := checkClipboard(&Context{
		Goos: "linux",
		LookPathFn: func(file string) (string, error) {
			if file == "xclip" {
				return "/usr/bin/xclip", nil
			}
			return "", os.ErrNotExist
		},
	})
	if pass.Status != StatusPass {
		t.Fatalf("linux clipboard pass status = %s", pass.Status)
	}

	warn := checkClipboard(&Context{
		Goos: "linux",
		LookPathFn: func(string) (string, error) {
			return "", os.ErrNotExist
		},
	})
	if warn.Status != StatusWarn || !strings.Contains(warn.Message, "xclip") {
		t.Fatalf("linux clipboard warn = %+v", warn)
	}

	other := checkClipboard(&Context{Goos: "freebsd"})
	if other.Status != StatusWarn {
		t.Fatalf("other os clipboard status = %s, want WARN", other.Status)
	}
}

func TestCheckOfflineProxyEnv(t *testing.T) {
	ctx := &Context{
		GetenvFn: func(key string) string {
			if key == "HTTP_PROXY" {
				return "http://proxy.local"
			}
			return ""
		},
	}
	warn := checkOfflineProxyEnv(ctx)
	if warn.Status != StatusWarn || !strings.Contains(warn.Message, "HTTP_PROXY") {
		t.Fatalf("proxy warning = %+v", warn)
	}

	pass := checkOfflineProxyEnv(&Context{GetenvFn: func(string) string { return "" }})
	if pass.Status != StatusPass {
		t.Fatalf("expected pass when proxy env unset, got %+v", pass)
	}
}

func TestDetectCI(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "github", env: map[string]string{"GITHUB_ACTIONS": "true"}, want: "GitHub Actions"},
		{name: "gitlab", env: map[string]string{"GITLAB_CI": "true"}, want: "GitLab CI"},
		{name: "jenkins", env: map[string]string{"JENKINS_URL": "https://jenkins.local"}, want: "Jenkins"},
		{name: "unknown ci", env: map[string]string{"CI": "1"}, want: "CI (unknown provider)"},
		{name: "none", env: map[string]string{}, want: ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := detectCI(func(key string) string { return tt.env[key] })
			if got != tt.want {
				t.Fatalf("detectCI() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCandidateExecutableNames(t *testing.T) {
	if got := candidateExecutableNames("git", "darwin", ""); len(got) != 1 || got[0] != "git" {
		t.Fatalf("non-windows candidates = %v", got)
	}

	win := candidateExecutableNames("git", "windows", ".EXE;.BAT")
	if len(win) != 2 || win[0] != "git.EXE" || win[1] != "git.BAT" {
		t.Fatalf("windows candidates = %v", win)
	}

	withExt := candidateExecutableNames("git.exe", "windows", ".EXE")
	if len(withExt) != 1 || withExt[0] != "git.exe" {
		t.Fatalf("windows explicit ext candidates = %v", withExt)
	}

	defaultExts := candidateExecutableNames("git", "windows", "")
	if len(defaultExts) != 4 ||
		defaultExts[0] != "git.EXE" ||
		defaultExts[1] != "git.BAT" ||
		defaultExts[2] != "git.CMD" ||
		defaultExts[3] != "git.COM" {
		t.Fatalf("windows default candidates = %v", defaultExts)
	}
}

func TestParseOSRelease(t *testing.T) {
	rawPretty := []byte("NAME=Ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.2 LTS\"\nVERSION_ID=\"24.04\"\n")
	if got := parseOSRelease(rawPretty); got != "Ubuntu 24.04.2 LTS" {
		t.Fatalf("parseOSRelease(pretty) = %q", got)
	}

	rawFallback := []byte("NAME=Debian\nVERSION_ID=\"12\"\n")
	if got := parseOSRelease(rawFallback); got != "Debian 12" {
		t.Fatalf("parseOSRelease(fallback) = %q", got)
	}

	rawNameOnly := []byte("NAME=\"Alpine Linux\"\n")
	if got := parseOSRelease(rawNameOnly); got != "Alpine Linux" {
		t.Fatalf("parseOSRelease(name-only) = %q", got)
	}

	rawInvalid := []byte("# comment only\n")
	if got := parseOSRelease(rawInvalid); got != "" {
		t.Fatalf("parseOSRelease(invalid) = %q, want empty", got)
	}
}

func TestLookPathInEnv(t *testing.T) {
	tmp := t.TempDir()
	exeName := "mytool"
	if runtime.GOOS == "windows" {
		exeName = "mytool.exe"
	}
	path := filepath.Join(tmp, exeName)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("PATH", tmp)
	if runtime.GOOS == "windows" {
		t.Setenv("PATHEXT", ".EXE")
	}

	found, err := LookPathInEnv("mytool")
	if err != nil {
		t.Fatalf("LookPathInEnv() error = %v", err)
	}
	if found != path {
		t.Fatalf("LookPathInEnv() = %q, want %q", found, path)
	}

	_, err = LookPathInEnv("does-not-exist")
	if err == nil {
		t.Fatal("expected not found error")
	}
}

func TestIsDirectoryWritable_Failure(t *testing.T) {
	nonexistent := filepath.Join(t.TempDir(), "missing-dir")
	if err := IsDirectoryWritable(nonexistent); err == nil {
		t.Fatal("expected failure for missing directory")
	}
}

func TestCoreChecksAndBinaryChecks(t *testing.T) {
	version := checkVersionInfo(&Context{
		StaveVersion: "v1.2.3",
		GoVersion:    "go1.26.1",
		Goos:         "darwin",
		Goarch:       "arm64",
		BinaryPath:   "/usr/local/bin/stave",
	})
	if version.Status != StatusPass || !strings.Contains(version.Message, "stave_version=v1.2.3") {
		t.Fatalf("version check = %+v", version)
	}

	shell := checkShell(&Context{
		GetenvFn: func(key string) string {
			if key == "SHELL" {
				return "/bin/bash"
			}
			return ""
		},
	})
	if shell.Name != "shell" || shell.Status != StatusPass {
		t.Fatalf("shell check = %+v", shell)
	}

	ci := checkCI(&Context{
		GetenvFn: func(key string) string {
			if key == "GITHUB_ACTIONS" {
				return "true"
			}
			return ""
		},
	})
	if ci.Name != "ci-environment" || ci.Status != StatusPass {
		t.Fatalf("ci check = %+v", ci)
	}

	_ = checkContainer(&Context{}) // environment-dependent; ensure call path is exercised

	writable := checkWorkspaceWritable(&Context{Cwd: t.TempDir()})
	if writable.Status != StatusPass {
		t.Fatalf("workspace writable check = %+v", writable)
	}
	notWritable := checkWorkspaceWritable(&Context{Cwd: filepath.Join(t.TempDir(), "missing")})
	if notWritable.Status != StatusFail {
		t.Fatalf("workspace fail check = %+v", notWritable)
	}

	passCtx := &Context{
		LookPathFn: func(string) (string, error) { return "/usr/bin/tool", nil },
	}
	warnCtx := &Context{
		LookPathFn: func(string) (string, error) { return "", os.ErrNotExist },
	}

	if c := checkGit(passCtx); c.Status != StatusPass {
		t.Fatalf("git pass = %+v", c)
	}
	if c := checkGit(warnCtx); c.Status != StatusWarn {
		t.Fatalf("git warn = %+v", c)
	}
	if c := checkAWS(passCtx); c.Status != StatusPass {
		t.Fatalf("aws pass = %+v", c)
	}
	if c := checkAWS(warnCtx); c.Status != StatusWarn {
		t.Fatalf("aws warn = %+v", c)
	}
	if c := checkJQ(passCtx); c.Status != StatusPass {
		t.Fatalf("jq pass = %+v", c)
	}
	if c := checkJQ(warnCtx); c.Status != StatusWarn {
		t.Fatalf("jq warn = %+v", c)
	}
	if c := checkGraphviz(passCtx); c.Status != StatusPass {
		t.Fatalf("graphviz pass = %+v", c)
	}
	if c := checkGraphviz(warnCtx); c.Status != StatusWarn {
		t.Fatalf("graphviz warn = %+v", c)
	}
}

func TestCheckBinary_EmptyBinaryName(t *testing.T) {
	c := checkBinary(&Context{}, BinaryRequest{Name: "empty-bin"})
	if c.Status != StatusFail {
		t.Fatalf("expected FAIL for empty binary name, got %+v", c)
	}
}

func TestDetectOSAndContainerHelpers(t *testing.T) {
	// Unsupported OS should return empty quickly.
	if got := detectOSVersion("plan9"); got != "" {
		t.Fatalf("detectOSVersion(plan9) = %q, want empty", got)
	}

	// Run the platform branch to exercise file-read path; output is environment-dependent.
	_ = detectOSVersion(runtime.GOOS)
	_ = detectContainer()
}
