package architecture_test

// Extracted rules codified as tests. Each test enforces a rule from
// docs-internal/extracted-rules.md that was classified as TESTABLE-CODE.
// Source rules are annotated with <!-- ENFORCED BY: TestXxx -->.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/cli/ui"
)

// C2: Exit codes match the platform contract documented in CLAUDE.md.
func TestExitCodeConstants(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"ExitSuccess", ui.ExitSuccess, 0},
		{"ExitSecurity", ui.ExitSecurity, 1},
		{"ExitInputError", ui.ExitInputError, 2},
		{"ExitViolations", ui.ExitViolations, 3},
		{"ExitInternal", ui.ExitInternal, 4},
		{"ExitIndeterminate", ui.ExitIndeterminate, 5},
		{"ExitAttestationFailed", ui.ExitAttestationFailed, 6},
		{"ExitInterrupted", ui.ExitInterrupted, 130},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

// C10/C11/C44: No duplicate ParseARN functions outside arn.go.
func TestNoDuplicateARNParser(t *testing.T) {
	pattern := regexp.MustCompile(`func\s+[Pp]arse[Aa][Rr][Nn]\b`)

	// parseARNContext in remediation/formatter.go is a lightweight
	// extraction (account+region only) in core/, which cannot import
	// platform/providers/aws/iam/arn.go. Accepted per hexagonal boundary.
	allowed := map[string]bool{
		filepath.Clean("../internal/core/evaluation/remediation/formatter.go"): true,
	}
	var violations []string

	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == ".git" || base == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "arn.go") || strings.Contains(path, "_test.go") {
			return nil
		}
		if allowed[filepath.Clean(path)] {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if pattern.Match(data) {
			violations = append(violations, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, v := range violations {
		t.Errorf("duplicate ARN parser in %s (must use internal/platform/providers/aws/iam/arn.go)", v)
	}
}

// C27: Chain definitions live in chains/, not inline in control YAML.
func TestNoInlineChainDefinitions(t *testing.T) {
	pattern := regexp.MustCompile(`(?i)chain_id|compound_severity|postconditions`)
	var violations []string

	err := filepath.Walk("../internal/controls", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if pattern.Match(data) {
			violations = append(violations, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, v := range violations {
		t.Errorf("chain definition in control YAML %s (must be in chains/)", v)
	}
}

// C36: S3 controls live in controls/s3/.
func TestS3ControlsLocation(t *testing.T) {
	s3Pattern := regexp.MustCompile(`(?i)^id:\s*CTL\.S3\.`)
	var violations []string

	err := filepath.Walk("../internal/controls", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		rel, _ := filepath.Rel("../internal/controls", path)
		if strings.HasPrefix(rel, "s3"+string(filepath.Separator)) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if s3Pattern.Match(data) {
			violations = append(violations, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, v := range violations {
		t.Errorf("S3 control outside controls/s3/: %s", v)
	}
}

// C21: cobra.Command with RunE must set SilenceUsage and SilenceErrors.
func TestCobraCommandsSilenceFlags(t *testing.T) {
	runePattern := regexp.MustCompile(`RunE\s*:`)
	silenceUsage := regexp.MustCompile(`SilenceUsage\s*:\s*true`)
	silenceErrors := regexp.MustCompile(`SilenceErrors\s*:\s*true`)

	var violations []string

	err := filepath.Walk("../cmd", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.Contains(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		content := string(data)
		if !runePattern.MatchString(content) {
			return nil
		}
		if !silenceUsage.MatchString(content) || !silenceErrors.MatchString(content) {
			violations = append(violations, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, v := range violations {
		t.Errorf("%s has RunE but missing SilenceUsage/SilenceErrors: true", v)
	}
}

// C6/S8: Testscript txtar files that invoke `stave apply` should include
// --eval-time for deterministic output. Only checks .txtar files where
// the apply invocation is a real command (not help text or comments).
func TestEvalTimeInTestscripts(t *testing.T) {
	applyCmd := regexp.MustCompile(`(?m)^exec stave apply\b`)
	evalTimeFlag := regexp.MustCompile(`--eval-time`)

	var violations []string

	err := filepath.Walk("../cmd/stave/testdata/scripts", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".txtar") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		content := string(data)
		if !applyCmd.MatchString(content) {
			return nil
		}
		// Check that every `exec stave apply` line includes --eval-time.
		for line := range strings.SplitSeq(content, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "exec stave apply") {
				continue
			}
			if !evalTimeFlag.MatchString(line) && !strings.Contains(line, "--now") {
				// Allow lines testing non-time-sensitive behavior.
				if strings.Contains(line, "--dry-run") ||
					strings.Contains(line, "--help") ||
					strings.Contains(line, "validate") {
					continue
				}
				violations = append(violations, filepath.Base(path)+": "+line)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, v := range violations {
		t.Errorf("testscript apply without --eval-time: %s", v)
	}
}

// F15: README.md must not contain Go Report Card badge or link.
func TestNoGoReportCardInReadme(t *testing.T) {
	data, err := os.ReadFile("../README.md")
	if err != nil {
		t.Skipf("README.md not found: %v", err)
	}
	if strings.Contains(strings.ToLower(string(data)), "goreportcard") {
		t.Error("README.md contains Go Report Card reference (forbidden)")
	}
}

// A12: SLA ladder invariant — severity ordering on finding_sla.go exports.
// Checks that the HasSLA/IsAnyBreach/IsOverdue API is structurally present.
func TestSLALadderAPIExists(t *testing.T) {
	data, err := os.ReadFile("../internal/core/evaluation/finding_sla.go")
	if err != nil {
		t.Fatalf("read finding_sla.go: %v", err)
	}
	content := string(data)
	for _, method := range []string{"HasSLA", "IsAnyBreach", "IsOverdue", "RehydrateSLA"} {
		if !strings.Contains(content, "func (f *Finding) "+method) &&
			!strings.Contains(content, "func (f Finding) "+method) {
			t.Errorf("finding_sla.go missing SLA ladder method %s", method)
		}
	}
}

// C23: Stable flag names are centralized in cliflags package.
func TestStableFlagNamesExist(t *testing.T) {
	data, err := os.ReadFile("../cmd/cmdutil/cliflags/flags.go")
	if err != nil {
		t.Fatalf("read cliflags/flags.go: %v", err)
	}
	content := string(data)

	// These flag constants must exist in cliflags to prevent typos.
	stableFlags := []string{
		`FlagControls`,
		`FlagFormat`,
		`FlagQuiet`,
		`FlagSanitize`,
	}
	for _, flag := range stableFlags {
		if !strings.Contains(content, flag) {
			t.Errorf("cliflags/flags.go missing stable flag constant %s", flag)
		}
	}

	// Controls has a dedicated registration helper.
	if !strings.Contains(content, "RegisterControlsFlag") {
		t.Error("cliflags/flags.go missing RegisterControlsFlag helper")
	}
}
