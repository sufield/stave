package architecture_test

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation"
)

const adrDir = "docs-internal/architecture/decisions"

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir != "/" {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find repo root (go.mod)")
	return ""
}

func TestADR001_MetadataNotDirectlySerialized(t *testing.T) {
	rt := reflect.TypeFor[evaluation.ComplianceReport]()
	f, ok := rt.FieldByName("Metadata")
	if !ok {
		t.Fatal("ComplianceReport.Metadata field not found")
	}
	tag := f.Tag.Get("json")
	if tag != "-" {
		t.Fatalf("ADR-001 violation: Metadata json tag is %q, want %q.\n"+
			"  Direct serialization would double-count metadata in output.\n"+
			"  See %s/ADR-001-metadata-json-dash.md", tag, "-", adrDir)
	}
}

func TestADR002_ApplyUsesFacade(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "cmd/apply/run_standard.go"))
	if err != nil {
		t.Fatalf("read run_standard.go: %v", err)
	}
	src := string(data)
	if !strings.Contains(src, `"github.com/sufield/stave/pkg/stave"`) {
		t.Fatalf("ADR-002 violation: cmd/apply/run_standard.go does not import pkg/stave.\n"+
			"  The live apply path must route through the facade.\n"+
			"  See %s/ADR-002-apply-facade-routing.md", adrDir)
	}
	if strings.Contains(src, `"github.com/sufield/stave/internal/app/eval/options"`) {
		t.Fatalf("ADR-002 violation: cmd/apply/run_standard.go imports internal/app/eval/options.\n"+
			"  The ParsedOptions path is abandoned.\n"+
			"  See %s/ADR-002-apply-facade-routing.md", adrDir)
	}
}

func TestADR003_ExtensionsDTOIntegrity(t *testing.T) {
	rt := reflect.TypeFor[evaluation.Extensions]()
	f, ok := rt.FieldByName("Integrity")
	if !ok {
		t.Fatalf("ADR-003 violation: Extensions struct has no Integrity field.\n"+
			"  Verified and unverified evaluations must produce different output.\n"+
			"  See %s/ADR-003-extensions-dto-integrity.md", adrDir)
	}
	if f.Type.Kind() != reflect.Pointer {
		t.Fatalf("ADR-003 violation: Extensions.Integrity should be a pointer (omittable), got %s.\n"+
			"  See %s/ADR-003-extensions-dto-integrity.md", f.Type.Kind(), adrDir)
	}
}

func TestADR004_CrossAssetChainsUseGlobalScope(t *testing.T) {
	root := repoRoot(t)
	chainsDir := filepath.Join(root, "internal", "chains")
	entries, err := os.ReadDir(chainsDir)
	if err != nil {
		t.Fatalf("read chains dir: %v", err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(chainsDir, e.Name()))
		if err != nil {
			continue
		}
		content := string(data)
		// Chains with multiple applicable_asset_types entries need scope: global
		lines := strings.Split(content, "\n")
		assetTypeCount := 0
		hasGlobalScope := strings.Contains(content, "scope: global")
		inAssetTypes := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "applicable_asset_types:") {
				inAssetTypes = true
				continue
			}
			if inAssetTypes {
				if strings.HasPrefix(trimmed, "- ") {
					assetTypeCount++
				} else {
					inAssetTypes = false
				}
			}
		}
		if assetTypeCount > 1 && !hasGlobalScope {
			t.Errorf("ADR-004 violation: chain %s has %d asset types but no scope: global.\n"+
				"  Cross-asset chains silently fail without global scope.\n"+
				"  See %s/ADR-004-cross-asset-scope-global.md", e.Name(), assetTypeCount, adrDir)
		}
	}
}

func TestADR005_IntegrityFlagsReachApplycore(t *testing.T) {
	root := repoRoot(t)
	cmdData, err := os.ReadFile(filepath.Join(root, "cmd/apply/cmd.go"))
	if err != nil {
		t.Fatalf("read cmd/apply/cmd.go: %v", err)
	}
	if !strings.Contains(string(cmdData), "integrity-manifest") {
		t.Fatalf("ADR-005 violation: cmd/apply/cmd.go does not define --integrity-manifest flag.\n"+
			"  Integrity verification silently skipped without this flag.\n"+
			"  See %s/ADR-005-integrity-applycore-path.md", adrDir)
	}
}

func TestADR006_SignSnapshotRejectsNonAssets(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "pkg/stave/attest.go"))
	if err != nil {
		t.Fatalf("read attest.go: %v", err)
	}
	if !strings.Contains(string(data), "file contains no assets array") {
		t.Fatalf("ADR-006 violation: SignSnapshot does not reject files without assets.\n"+
			"  Signing non-observation files succeeds silently, producing unusable attestations.\n"+
			"  See %s/ADR-006-sign-snapshot-rejects-non-assets.md", adrDir)
	}
}

func TestADR007_AttestVerifyPrintsFailure(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "cmd/attest/cmd.go"))
	if err != nil {
		t.Fatalf("read cmd/attest/cmd.go: %v", err)
	}
	if !strings.Contains(string(data), "Attestation failed") {
		t.Fatalf("ADR-007 violation: attest verify does not print failure reason.\n"+
			"  Verification failure produces no diagnostic output.\n"+
			"  See %s/ADR-007-attest-verify-prints-failure.md", adrDir)
	}
}

func TestADR008_FixturesAreCommittedArtifacts(t *testing.T) {
	root := repoRoot(t)
	waDir := filepath.Join(root, "internal", "fixtures", "labs", "wa-lenses")
	var jsonFiles int
	_ = filepath.WalkDir(waDir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".json") {
			jsonFiles++
		}
		return nil
	})
	if jsonFiles == 0 {
		t.Fatalf("ADR-008 violation: fixtures/labs/wa-lenses/ contains no committed JSON files.\n"+
			"  WA Lens fixtures require domain knowledge and must be committed artifacts.\n"+
			"  See %s/ADR-008-fixtures-committed-artifacts.md", adrDir)
	}
}

func TestADR009_DemoScriptsNoSetE(t *testing.T) {
	root := repoRoot(t)
	examplesDir := filepath.Join(root, "examples")
	_ = filepath.WalkDir(examplesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "run.sh" {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", path, readErr)
		}
		content := string(data)
		if !strings.Contains(content, "stave") {
			return nil
		}
		if strings.Contains(content, "set -euo pipefail") {
			rel, _ := filepath.Rel(root, path)
			t.Errorf("ADR-009 violation: %s uses set -euo pipefail.\n"+
				"  stave exits 3 on findings; -e aborts demos on expected findings.\n"+
				"  Use set -uo pipefail instead.\n"+
				"  See %s/ADR-009-demo-scripts-no-set-e.md", rel, adrDir)
		}
		return nil
	})
}

func TestADR010_ExitCodeConvention(t *testing.T) {
	if ui.ExitViolations != 3 {
		t.Fatalf("ADR-010 violation: ExitViolations is %d, want 3.\n"+
			"  Exit 3 = policy violation, exit 1 = tool error.\n"+
			"  See %s/ADR-010-exit-code-convention.md", ui.ExitViolations, adrDir)
	}
}

func TestADR012_AliasResolverOnAllLoaders(t *testing.T) {
	root := repoRoot(t)
	var violations []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == "vendor" || base == ".git" || base == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", path, readErr)
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if !strings.Contains(line, "NewControlLoader(") {
				continue
			}
			// Definition site — skip
			if strings.Contains(line, "func NewControlLoader") {
				continue
			}
			// Check this line and next 3 for WithAliasResolver
			end := min(i+4, len(lines))
			window := strings.Join(lines[i:end], "\n")
			if !strings.Contains(window, "WithAliasResolver") {
				rel, _ := filepath.Rel(root, path)
				violations = append(violations, fmt.Sprintf("%s:%d", rel, i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, v := range violations {
		t.Errorf("ADR-012 violation: NewControlLoader without WithAliasResolver at %s.\n"+
			"  Controls with unsafe_predicate_alias silently produce no findings.\n"+
			"  See %s/ADR-012-alias-resolver-all-loaders.md", v, adrDir)
	}
}

func TestADR013_CoreNoCloudProviderLiterals(t *testing.T) {
	// Ratchet: cloud-provider literals in core code (non-comment, non-test)
	// must not increase. The baseline covers deferred LOW-priority
	// violations (sirfacts, risk, translation). Each cleanup lowers it.
	const baseline = 74

	root := repoRoot(t)
	coreDir := filepath.Join(root, "internal", "core")

	patterns := []string{
		"aws_", "gcp_", "azure_",
		".amazonaws.com", ".googleapi.com", ".azure.com",
	}

	count := 0
	err := filepath.WalkDir(coreDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, openErr := os.Open(path)
		if openErr != nil {
			return fmt.Errorf("open %s: %w", path, openErr)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			for _, pat := range patterns {
				if strings.Contains(line, pat) {
					count++
					break
				}
			}
		}
		return scanner.Err()
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if count > baseline {
		t.Fatalf("ADR-013 violation: cloud-provider literals in core increased (%d > baseline %d).\n"+
			"  Move new cloud-specific code to internal/platform/providers/ or internal/adapters/.\n"+
			"  See %s/ADR-013-core-cloud-agnosticism.md", count, baseline, adrDir)
	}
	if count < baseline {
		t.Logf("ADR-013: count decreased (%d < %d) — update baseline in this test", count, baseline)
	}
}
