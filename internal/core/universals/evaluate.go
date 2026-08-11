package universals

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var universalNames = map[string]string{
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

// EvaluateConfig holds parameters for a universal evaluation run.
type EvaluateConfig struct {
	FormulaDir    string // directory containing *.smt2 files
	GroundingPath string // path to grounding-map.yaml (empty = co-located with formulas)
	Assets        []asset
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
// using Z3 subprocess and returns a summary.
func EvaluateAll(cfg EvaluateConfig) (*Summary, error) {
	if _, err := exec.LookPath("z3"); err != nil {
		return nil, errors.New("z3 not found in PATH — install with: apt install z3")
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
		r := evaluateOne(f, cfg.Assets, gm)
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
	id      string
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

	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out, nil
}

func extractID(filename string) string {
	m := idPattern.FindStringSubmatch(filename)
	if len(m) < 2 {
		return filename
	}
	return "U" + m[1]
}

func evaluateOne(f formula, assets []asset, gm *GroundingMap) Result {
	r := Result{ID: f.id, Name: f.name}

	ug, ok := gm.Universals[f.id]
	if !ok {
		r.Verdict = "skip"
		r.Error = "no grounding map entry for " + f.id
		return r
	}

	gs := GroundAssets(assets, ug)
	r.Grounded = len(gs)
	r.Vacuous = len(gs) == 0

	grounding := GenerateGrounding(ug.Sort, ug.Predicates, gs)
	combined := insertGrounding(f.content, grounding)

	start := time.Now()
	verdict, _ := runZ3(combined)
	r.SolveTimeMs = time.Since(start).Milliseconds()
	r.Verdict = verdict

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

func runZ3(formulaContent string) (result, output string) {
	tmp, err := os.CreateTemp("", "prove-*.smt2")
	if err != nil {
		return "error", err.Error()
	}
	defer os.Remove(tmp.Name())
	_, _ = fmt.Fprint(tmp, formulaContent)
	_ = tmp.Close()

	cmd := exec.Command("z3", tmp.Name()) //nolint:gosec,noctx // z3 binary with temp file; no cancellation needed
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run()

	out := strings.TrimSpace(stdout.String())
	lines := strings.Split(out, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		switch line {
		case "sat", "unsat", "unknown":
			return line, out
		}
	}
	return "error", out + "\n" + stderr.String()
}
