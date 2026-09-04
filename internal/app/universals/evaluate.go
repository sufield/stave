package universals

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var universalNames = map[UniversalID]string{
	"U26": "Service-level logging enabled",
	"U27": "Endpoint authentication required",
	"U28": "Deletion protection enabled",
	"U29": "Backup configured",
	"U30": "No plaintext secrets in config",
	"U31": "Version currency maintained",
	"U32": "IMDSv2 enforced on compute",
	"U33": "Required security services enabled",
}

var idPattern = regexp.MustCompile(`^u(\d+)-`)

// Solver runs an SMT-LIB formula and returns "sat", "unsat", "unknown", or "error".
type Solver func(formula string) (verdict string, output string)

// EvaluateConfig holds parameters for a universal evaluation run.
type EvaluateConfig struct {
	FormulaDir    string // directory containing *.smt2 files
	GroundingPath string // path to grounding-map.yaml (empty = co-located with formulas)
	Assets        []asset
	Solver        Solver // injected Z3 runner
}

// LoadGroundingMap reads and parses the grounding-map.yaml.
func LoadGroundingMap(path string) (*GroundingMap, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from user flag, validated upstream
	if err != nil {
		return nil, fmt.Errorf("read grounding map: %w", err)
	}
	var gm GroundingMap
	if err := yaml.Unmarshal(data, &gm); err != nil {
		return nil, fmt.Errorf("parse grounding map: %w", err)
	}
	return &gm, nil
}

// LoadAssetsFromDir reads observation JSON files and returns deduplicated assets.
func LoadAssetsFromDir(dir string) ([]asset, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("glob observations: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no observation files in %s", dir)
	}

	var all []asset
	seen := map[string]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f) //nolint:gosec // path from user-provided observations dir
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		var snap struct {
			Assets []struct {
				ID         string         `json:"id"`
				Type       string         `json:"type"`
				Properties map[string]any `json:"properties"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(data, &snap); err != nil {
			return nil, fmt.Errorf("parse %s: %w", f, err)
		}
		for _, a := range snap.Assets {
			if !seen[a.ID] {
				all = append(all, asset{ID: a.ID, Type: a.Type, Properties: a.Properties})
				seen[a.ID] = true
			}
		}
	}
	return all, nil
}

// EvaluateAll runs all universal formulas against the provided assets
// using the injected solver and returns a summary.
func EvaluateAll(cfg EvaluateConfig) (*Summary, error) {
	if cfg.Solver == nil {
		return nil, errors.New("no solver provided")
	}

	groundingPath := cfg.GroundingPath
	if groundingPath == "" {
		groundingPath = filepath.Join(cfg.FormulaDir, "grounding-map.yaml")
	}

	gm, err := LoadGroundingMap(groundingPath)
	if err != nil {
		return nil, err
	}

	formulas, err := loadFormulas(cfg.FormulaDir)
	if err != nil {
		return nil, err
	}

	summary := &Summary{Total: len(formulas)}
	for _, f := range formulas {
		r := evaluateOne(f, cfg.Assets, gm, cfg.Solver)
		summary.Results = append(summary.Results, r)
		switch {
		case r.Error != "":
			summary.Errored++
		case r.Holds:
			summary.Hold++
		default:
			summary.Violated++
		}
	}
	return summary, nil
}

type formula struct {
	id      UniversalID
	name    string
	content string
}

func loadFormulas(dir string) ([]formula, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read formula dir: %w", err)
	}

	var out []formula
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".smt2") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // formula dir from user flag
		if err != nil {
			return nil, fmt.Errorf("read formula %s: %w", e.Name(), err)
		}
		id := extractID(e.Name())
		name := universalNames[id]
		if name == "" {
			name = e.Name()
		}
		out = append(out, formula{id: id, name: name, content: string(data)})
	}

	slices.SortFunc(out, func(a, b formula) int { return cmp.Compare(a.id, b.id) })
	return out, nil
}

func extractID(filename string) UniversalID {
	m := idPattern.FindStringSubmatch(filename)
	if len(m) < 2 {
		return UniversalID(filename)
	}
	return UniversalID("U" + m[1])
}

func evaluateOne(f formula, assets []asset, gm *GroundingMap, solve Solver) Result {
	r := Result{ID: f.id, Name: f.name}

	ug, ok := gm.Universals[f.id]
	if !ok {
		r.Verdict = "skip"
		r.Error = "no grounding map entry for " + string(f.id)
		return r
	}

	gs := GroundAssets(assets, ug)
	r.Grounded = len(gs)
	r.Vacuous = len(gs) == 0

	grounding := GenerateGrounding(ug.Sort, ug.Predicates, gs)
	combined := insertGrounding(f.content, grounding)

	start := time.Now()
	verdict, _ := solve(combined)
	r.SolveTimeMs = time.Since(start).Milliseconds()
	r.Verdict = Verdict(verdict)

	switch verdict {
	case "unsat":
		r.Holds = true
	case "sat":
		r.Holds = false
		r.Violations = extractViolations(gs, ug)
	default:
		r.Error = "z3 returned " + verdict
	}

	return r
}

func extractViolations(gs []grounded, ug UniversalGrounding) []Violation {
	var out []Violation
	for _, g := range gs {
		for _, pred := range ug.Predicates {
			val, ok := g.preds[pred]
			if !ok {
				continue
			}
			if !val {
				out = append(out, Violation{
					Constant:  g.name,
					Predicate: pred,
					Value:     val,
				})
			}
		}
	}
	return out
}

func insertGrounding(formulaContent, grounding string) string {
	const marker = "(push 1)"
	idx := strings.Index(formulaContent, marker)
	if idx == -1 {
		return formulaContent
	}
	return formulaContent[:idx] + grounding + "\n" + formulaContent[idx:]
}
