package doctor

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/doctor"
)

func TestRunDoctorChecksReportsPasses(t *testing.T) {
	dir := t.TempDir()
	lookPath := func(file string) (string, error) { return "/usr/bin/" + file, nil }
	getenv := func(key string) string { return "" }

	checks, hasFail := doctor.Run(doctor.Context{
		Cwd:        dir,
		BinaryPath: "/usr/local/bin/stave",
		LookPathFn: lookPath,
		GetenvFn:   getenv,
		Goos:       "darwin",
	})
	if hasFail {
		t.Fatal("expected no failing checks")
	}
	if len(checks) == 0 {
		t.Fatal("expected checks")
	}

	var hasWritablePass bool
	var hasGitPass bool
	var hasAWSPass bool
	for _, c := range checks {
		if c.Name == "workspace-writable" && c.Status == doctor.StatusPass {
			hasWritablePass = true
		}
		if c.Name == "git" && c.Status == doctor.StatusPass {
			hasGitPass = true
		}
		if c.Name == "aws-cli" && c.Status == doctor.StatusPass {
			hasAWSPass = true
		}
	}
	if !hasWritablePass {
		t.Fatalf("expected workspace-writable PASS, got: %+v", checks)
	}
	if !hasGitPass {
		t.Fatalf("expected git PASS, got: %+v", checks)
	}
	if !hasAWSPass {
		t.Fatalf("expected aws-cli PASS, got: %+v", checks)
	}
}

func TestRunDoctorChecksReportsWarnings(t *testing.T) {
	dir := t.TempDir()
	lookPath := func(file string) (string, error) { return "", errors.New("not found") }
	getenv := func(key string) string {
		if key == "HTTP_PROXY" {
			return "http://proxy.example.com:8080"
		}
		return ""
	}

	checks, hasFail := doctor.Run(doctor.Context{
		Cwd:        dir,
		BinaryPath: "",
		LookPathFn: lookPath,
		GetenvFn:   getenv,
		Goos:       "linux",
	})
	if hasFail {
		t.Fatal("expected no hard failures")
	}

	var sawJQWarn bool
	var sawGitWarn bool
	var sawAWSWarn bool
	var sawProxyWarn bool
	for _, c := range checks {
		if c.Name == "git" && c.Status == doctor.StatusWarn {
			sawGitWarn = true
		}
		if c.Name == "aws-cli" && c.Status == doctor.StatusWarn {
			sawAWSWarn = true
		}
		if c.Name == "jq" && c.Status == doctor.StatusWarn {
			sawJQWarn = true
		}
		if c.Name == "offline-proxy-env" && c.Status == doctor.StatusWarn {
			sawProxyWarn = true
		}
	}
	if !sawJQWarn {
		t.Fatalf("expected jq warning, got: %+v", checks)
	}
	if !sawGitWarn {
		t.Fatalf("expected git warning, got: %+v", checks)
	}
	if !sawAWSWarn {
		t.Fatalf("expected aws-cli warning, got: %+v", checks)
	}
	if !sawProxyWarn {
		t.Fatalf("expected proxy warning, got: %+v", checks)
	}
}

func TestCheckWritableDirFailsOnReadOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("chmod unsupported in this environment: %v", err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()

	err := doctor.CheckWritableDir(dir)
	// Some environments still allow write due to ownership/ACL behavior; don't hard-fail.
	if err == nil {
		t.Skip("read-only probe not enforceable in this environment")
	}
	if !strings.Contains(err.Error(), "permission") && !strings.Contains(err.Error(), "denied") {
		t.Fatalf("unexpected error: %v", err)
	}
}
