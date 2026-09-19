package architecture_test

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sufield/stave/internal/collectorcontract"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// ponytail: global map + mutex; per-test map if concurrency matters
var (
	qmMu      sync.Mutex
	qmMetrics = map[string]any{}
)

func qmRecord(t *testing.T, name string, value any) {
	t.Helper()
	qmMu.Lock()
	qmMetrics[name] = value
	qmMu.Unlock()
	t.Logf("METRIC %s = %v", name, value)
}

// ============================================================
// SIZE
// ============================================================

func TestMeasureKernelSize(t *testing.T) {
	lines := countGoLines(t, "../internal/core/evaluation/engine/", false)
	qmRecord(t, "kernel_code_lines", lines)
}

func TestMeasureEvaluationSize(t *testing.T) {
	lines := countGoLines(t, "../internal/core/evaluation/", false)
	qmRecord(t, "evaluation_code_lines", lines)
}

func TestMeasureDataToCodeRatio(t *testing.T) {
	catalogLines := countAllFileLines(t, "../internal/controls/", ".yaml")
	chainLines := countAllFileLines(t, "../internal/chains/", ".yaml")
	engineLines := countGoLines(t, "../internal/core/evaluation/engine/", false)
	ratio := float64(catalogLines+chainLines) / float64(engineLines)
	qmRecord(t, "data_to_code_ratio", fmt.Sprintf("%.1f", ratio))
	qmRecord(t, "catalog_yaml_lines", catalogLines)
	qmRecord(t, "chain_yaml_lines", chainLines)
}

func TestMeasureTotalControlCount(t *testing.T) {
	controls, _ := loadCatalog(t)
	qmRecord(t, "control_count", len(controls))
}

func TestMeasureChainCount(t *testing.T) {
	_, chains := loadCatalog(t)
	qmRecord(t, "chain_count", len(chains))
}

func TestMeasureServiceCount(t *testing.T) {
	entries, err := os.ReadDir("../internal/controls")
	if err != nil {
		t.Fatalf("read controls dir: %v", err)
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), "_") {
			count++
		}
	}
	qmRecord(t, "service_count", count)
}

// ============================================================
// COMPLEXITY (Go AST — no external tools)
// ============================================================

func TestMeasureMaxFunctionLength(t *testing.T) {
	maxLines, maxName := findMaxFuncLines(t, "../internal/core/evaluation/engine/")
	qmRecord(t, "engine_max_func_lines", maxLines)
	qmRecord(t, "engine_max_func_name", maxName)
}

func TestMeasureMaxFunctionParams(t *testing.T) {
	maxParams, maxName := findMaxFuncParams(t, "../internal/core/evaluation/engine/")
	qmRecord(t, "engine_max_func_params", maxParams)
	qmRecord(t, "engine_max_params_name", maxName)
}

// ============================================================
// COVERAGE
// ============================================================

func TestMeasureFixtureFileCount(t *testing.T) {
	count := 0
	if err := filepath.Walk("../internal/fixtures/", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".json") {
			count++
		}
		return nil
	}); err != nil {
		t.Fatalf("walk fixtures: %v", err)
	}
	qmRecord(t, "fixture_file_count", count)

	controls, _ := loadCatalog(t)
	if len(controls) > 0 {
		qmRecord(t, "fixture_to_control_ratio", fmt.Sprintf("%.2f", float64(count)/float64(len(controls))))
	}
}

// ============================================================
// CATALOG STRUCTURE (reuses loadCatalog)
// ============================================================

func TestMeasureOrphanControls(t *testing.T) {
	controls, chains := loadCatalog(t)
	referenced := make(map[string]bool)
	for _, ch := range chains {
		for _, cid := range ch.ControlIDs {
			referenced[string(cid)] = true
		}
	}
	var orphans int
	bySev := make(map[policy.Severity]int)
	for _, ctl := range controls {
		if !referenced[string(ctl.ID)] {
			orphans++
			bySev[ctl.Severity]++
		}
	}
	qmRecord(t, "orphan_controls_total", orphans)
	qmRecord(t, "orphan_controls_critical", bySev[policy.SeverityCritical])
}

func TestMeasureControlNamingViolations(t *testing.T) {
	controls, _ := loadCatalog(t)
	pattern := regexp.MustCompile(`^CTL\.[A-Z0-9]+(\.[A-Z0-9_.]+)?\.\d{3}$`)
	violations := 0
	for _, ctl := range controls {
		if !pattern.MatchString(string(ctl.ID)) {
			violations++
			if violations <= 5 {
				t.Logf("  naming: %s", ctl.ID)
			}
		}
	}
	qmRecord(t, "control_naming_violations", violations)
}

func TestMeasureSeverityDistribution(t *testing.T) {
	controls, _ := loadCatalog(t)
	bySev := make(map[string]int)
	for _, ctl := range controls {
		bySev[ctl.Severity.String()]++
	}
	qmRecord(t, "severity_distribution", bySev)
}

func TestMeasureDeadChains(t *testing.T) {
	controls, chains := loadCatalog(t)
	ctlIndex := make(map[string]bool, len(controls))
	for _, ctl := range controls {
		ctlIndex[string(ctl.ID)] = true
	}
	dead := 0
	for _, ch := range chains {
		for _, cid := range ch.ControlIDs {
			if !ctlIndex[string(cid)] {
				dead++
				if dead <= 5 {
					t.Logf("  dead ref: chain %s → %s", ch.ID, cid)
				}
				break
			}
		}
	}
	qmRecord(t, "dead_chains", dead)
}

func TestMeasurePredicateDuplication(t *testing.T) {
	controls, _ := loadCatalog(t)
	// Collect full predicate signatures (sorted rule sets) per control.
	signatures := make(map[string]int)
	for _, ctl := range controls {
		if ctl.UnsafePredicate.IsEmpty() {
			continue
		}
		var rules []string
		ctl.UnsafePredicate.Walk(func(r policy.PredicateRule) {
			rules = append(rules, fmt.Sprintf("%s|%s|%v", r.Field, r.Op, r.Value))
		})
		sort.Strings(rules)
		sig := strings.Join(rules, ";")
		signatures[sig]++
	}
	dupes := 0
	for _, count := range signatures {
		if count > 1 {
			dupes++
		}
	}
	qmRecord(t, "duplicate_predicates", dupes)
	qmRecord(t, "unique_predicates", len(signatures))
}

func TestMeasureGhostPropertyPaths(t *testing.T) {
	controls, _ := loadCatalog(t)
	contract, err := collectorcontract.Load()
	if err != nil {
		t.Skipf("collector contract not available: %v", err)
		return
	}
	contracted := contract.FieldIndex()
	ghosts := 0
	for _, ctl := range controls {
		ctl.UnsafePredicate.Walk(func(r policy.PredicateRule) {
			field := r.Field.String()
			if field == "" {
				return
			}
			field = strings.TrimPrefix(field, "properties.")
			if _, ok := contracted[field]; !ok {
				ghosts++
			}
		})
	}
	qmRecord(t, "ghost_property_paths", ghosts)
}

func TestMeasureMagicNumbersInPredicates(t *testing.T) {
	controls, _ := loadCatalog(t)
	magicPattern := regexp.MustCompile(`\b(22|80|443|3306|3389|5432|8080|8443|27017)\b`)
	magicCount := 0
	for _, ctl := range controls {
		ctl.UnsafePredicate.Walk(func(r policy.PredicateRule) {
			s := fmt.Sprintf("%v", r.Value)
			magicCount += len(magicPattern.FindAllString(s, -1))
		})
	}
	qmRecord(t, "magic_numbers_in_predicates", magicCount)
}

func TestMeasureUndocumentedExports(t *testing.T) {
	fset := token.NewFileSet()
	undocumented := 0
	if err := filepath.Walk("../internal/core/evaluation/engine", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Name.IsExported() && d.Doc == nil {
					undocumented++
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if ts, ok := spec.(*ast.TypeSpec); ok && ts.Name.IsExported() && d.Doc == nil {
						undocumented++
					}
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("walk engine: %v", err)
	}
	qmRecord(t, "engine_undocumented_exports", undocumented)
}

// ============================================================
// CONSISTENCY — GritQL
// ============================================================

func TestMeasureGritQLViolations(t *testing.T) {
	if _, err := os.Stat("../.grit"); os.IsNotExist(err) {
		t.Skip("no .grit directory")
	}
	// grit check exits non-zero on violations; count lines
	out, _ := runShell(t, "cd .. && grit check --grit-dir .grit internal/controls/ 2>&1 | grep -c 'error\\|warning' || true")
	qmRecord(t, "gritql_violations", strings.TrimSpace(out))
}

// ============================================================
// ARCHITECTURAL HEALTH
// ============================================================

func TestMeasureArchGoCompliance(t *testing.T) {
	// This test file already runs TestArchitecture; just record pass/fail
	qmRecord(t, "archgo_compliance", "measured_by_TestArchitecture")
}

func TestMeasureDepguardCompliance(t *testing.T) {
	qmRecord(t, "depguard_compliance", "measured_by_make_lint")
}

// ============================================================
// BUILD PERFORMANCE
// ============================================================

func TestMeasureBuildTime(t *testing.T) {
	if os.Getenv("QUALITY_FULL") == "" {
		t.Skip("set QUALITY_FULL=1 to measure build time")
	}
	start := time.Now()
	out, err := runShell(t, "cd .. && make build 2>&1")
	elapsed := time.Since(start)
	if err != nil {
		t.Skipf("make build failed: %s", out)
		return
	}
	qmRecord(t, "build_time_seconds", fmt.Sprintf("%.1f", elapsed.Seconds()))
}

func TestMeasureTestTime(t *testing.T) {
	if os.Getenv("QUALITY_FULL") == "" {
		t.Skip("set QUALITY_FULL=1 to measure test time")
	}
	start := time.Now()
	out, err := runShell(t, "cd .. && make test 2>&1")
	elapsed := time.Since(start)
	if err != nil {
		t.Skipf("make test failed: %s", out)
		return
	}
	qmRecord(t, "test_time_seconds", fmt.Sprintf("%.1f", elapsed.Seconds()))
}

// ============================================================
// WRITE METRICS — must run last (TestZ prefix sorts after TestM)
// ============================================================

func TestZWriteMetrics(t *testing.T) {
	qmMu.Lock()
	defer qmMu.Unlock()
	if len(qmMetrics) == 0 {
		t.Skip("no metrics collected")
	}
	out, err := json.MarshalIndent(qmMetrics, "", "  ")
	if err != nil {
		t.Fatalf("marshal metrics: %v", err)
	}
	if err := os.WriteFile("../docs-internal/quality-metrics.json", out, 0644); err != nil {
		t.Fatalf("write metrics: %v", err)
	}
	t.Logf("wrote %d metrics to docs-internal/quality-metrics.json", len(qmMetrics))
}

// ============================================================
// HELPERS
// ============================================================

func countGoLines(t *testing.T, dir string, includeTests bool) int {
	t.Helper()
	total := 0
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if !includeTests && strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		total += strings.Count(string(data), "\n")
		return nil
	}); err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return total
}

func countAllFileLines(t *testing.T, dir, ext string) int {
	t.Helper()
	total := 0
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ext) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		total += strings.Count(string(data), "\n")
		return nil
	}); err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return total
}

func findMaxFuncLines(t *testing.T, dir string) (int, string) {
	t.Helper()
	fset := token.NewFileSet()
	maxLines := 0
	maxName := ""
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			start := fset.Position(fn.Pos()).Line
			end := fset.Position(fn.End()).Line
			lines := end - start + 1
			if lines > maxLines {
				maxLines = lines
				maxName = fn.Name.Name
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return maxLines, maxName
}

func findMaxFuncParams(t *testing.T, dir string) (int, string) {
	t.Helper()
	fset := token.NewFileSet()
	maxParams := 0
	maxName := ""
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Type.Params == nil {
				continue
			}
			count := 0
			for _, field := range fn.Type.Params.List {
				if len(field.Names) == 0 {
					count++
				} else {
					count += len(field.Names)
				}
			}
			if count > maxParams {
				maxParams = count
				maxName = fn.Name.Name
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return maxParams, maxName
}

func runShell(t *testing.T, cmd string) (string, error) {
	t.Helper()
	c := exec.Command("bash", "-c", cmd)
	result, err := c.CombinedOutput()
	return string(result), err
}

// ============================================================
// SUMMARY — prints a sorted table for quick reading
// ============================================================

func TestZZPrintSummary(t *testing.T) {
	qmMu.Lock()
	defer qmMu.Unlock()
	if len(qmMetrics) == 0 {
		return
	}
	keys := make([]string, 0, len(qmMetrics))
	for k := range qmMetrics {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Log("=== Quality Metrics Summary ===")
	for _, k := range keys {
		t.Logf("  %-40s %v", k, qmMetrics[k])
	}
}
