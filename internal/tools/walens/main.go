// Command walens runs the monthly WA lens coverage check.
//
// It parses AWS Well-Architected custom lens JSONs to extract Security
// pillar best practices, runs Stave against the committed inverted
// fixtures, compares violation counts against the baseline scorecard,
// and writes an updated scorecard.
//
// Usage:
//
//	go run ./internal/tools/walens --lens-repo-path /tmp/wa-lenses
//	go run ./internal/tools/walens --lens-repo-path /tmp/wa-lenses --stave-bin ./stave
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type lens struct {
	Name    string   `json:"name"`
	Pillars []pillar `json:"pillars"`
}

type pillar struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Questions []question `json:"questions"`
}

type question struct {
	ID        string     `json:"id"`
	Title     string     `json:"title"`
	Choices   []choice   `json:"choices"`
	RiskRules []riskRule `json:"riskRules"`
}

type choice struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type riskRule struct {
	Condition string `json:"condition"`
	Risk      string `json:"risk"`
}

type staveOutput struct {
	Summary struct {
		TotalAssets int `json:"total_assets"`
		Violations  int `json:"violations"`
	} `json:"summary"`
	Status      string       `json:"status"`
	RiskSignals []riskSignal `json:"risk_signals"`
}

type riskSignal struct {
	ControlID string `json:"control_id"`
	AssetID   string `json:"asset_id"`
}

type lensStats struct {
	DirName    string
	LensName   string
	Total      int
	Invertible int
	Procedural int
}

type fixtureResult struct {
	Slug       string
	Violations int
	Controls   int
}

// lensToFixture maps lens directory names to fixture slugs.
// Lenses without a mapping have no committed fixture yet.
var lensToFixture = map[string]string{
	"Amazon-S3-Lens":           "s3",
	"Amazon-ECS-Lens":          "ecs",
	"Amazon-Cognito-Lens":      "cognito",
	"Amazon-MSK-Lens":          "msk",
	"DynamoDB":                 "dynamodb",
	"DocumentDB":               "documentdb",
	"ElastiCache":              "elasticache",
	"EMR-spark-lens":           "emr",
	"Glue":                     "glue",
	"OpenSearch":               "opensearch",
	"ApiGwLambda":              "lambda-apigw",
	"SageMaker-AutoGluon-lens": "sagemaker",
	"SageMaker-Flower-Lens":    "sagemaker",
	"Streaming-Media-Lens":     "streaming-media",
	"IDP-custom-lens":          "sagemaker",
	"Personalize":              "sagemaker",
	"Iceberg-S3-Lens":          "s3",
	"SaaS-Anywhere-Lens":       "sagemaker",
}

var proceduralRe = regexp.MustCompile(`(?i)\b(audit|review|periodically|regularly|process|procedure|train|awareness|document|assess|evaluate|establish|define|plan|incident\s+response|compliance\s+standard|company\s+wide|stakeholder)\b`)

// nanRe replaces bare NaN/Infinity tokens that some upstream lens JSONs contain.
var nanRe = regexp.MustCompile(`:\s*(NaN|-?Infinity)\b`)

func main() {
	lensRepo := flag.String("lens-repo-path", "/tmp/wa-lenses", "path to cloned wa-lens repo")
	staveBin := flag.String("stave-bin", "", "path to stave binary (default: $STAVE_BIN or ./stave)")
	fixtureDir := flag.String("fixture-dir", "internal/fixtures/labs/wa-lenses", "fixture directory")
	scorecardPath := flag.String("scorecard", "../docs-internal/experiments/wa-lens-scorecard.md", "scorecard path")
	evalTime := flag.String("eval-time", "", "eval-time for deterministic output (default: current time)")
	maxDelta := flag.Int("max-delta", 0, "max allowed violation increase per fixture (0 = no limit)")
	flag.Parse()

	if *staveBin == "" {
		*staveBin = os.Getenv("STAVE_BIN")
	}
	if *staveBin == "" {
		*staveBin = "./stave"
	}

	resolvedEvalTime := *evalTime
	if resolvedEvalTime == "" {
		resolvedEvalTime = time.Now().UTC().Format(time.RFC3339)
	}

	allStats, err := parseLensRepo(*lensRepo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse lens repo: %v\n", err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "parsed %d lenses with Security pillars\n", len(allStats))

	fixtureSlugs := discoverFixtures(*fixtureDir)
	if len(fixtureSlugs) == 0 {
		fmt.Fprintf(os.Stderr, "error: no fixtures found at %s — check the path\n", *fixtureDir)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "discovered %d fixture sets\n", len(fixtureSlugs))

	results := make(map[string]fixtureResult)
	for slug := range fixtureSlugs {
		r, err := evalFixture(*staveBin, *fixtureDir, slug, resolvedEvalTime)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: eval %s: %v\n", slug, err)
			continue
		}
		results[slug] = r
		fmt.Fprintf(os.Stderr, "  %s: %d violations, %d controls\n", slug, r.Violations, r.Controls)
	}

	baseline := readBaseline(*scorecardPath)

	regressed := false
	for slug, cur := range results {
		prev, ok := baseline[slug]
		if !ok {
			fmt.Fprintf(os.Stderr, "new fixture: %s (%d violations) — no baseline\n", slug, cur.Violations)
			continue
		}
		if cur.Violations < prev {
			fmt.Fprintf(os.Stderr, "REGRESSION: %s violations dropped %d → %d\n", slug, prev, cur.Violations)
			regressed = true
		} else if cur.Violations > prev {
			delta := cur.Violations - prev
			if *maxDelta > 0 && delta > *maxDelta {
				fmt.Fprintf(os.Stderr, "REGRESSION: %s violations spiked %d → %d (delta %d > max %d)\n",
					slug, prev, cur.Violations, delta, *maxDelta)
				regressed = true
			} else {
				fmt.Fprintf(os.Stderr, "improvement: %s violations rose %d → %d\n", slug, prev, cur.Violations)
			}
		}
	}

	// Detect new lenses without fixtures
	var unmappedNames []string
	for _, s := range allStats {
		if _, ok := lensToFixture[s.DirName]; !ok {
			fmt.Fprintf(os.Stderr, "new lens (no fixture): %s (%d invertible practices)\n", s.DirName, s.Invertible)
			unmappedNames = append(unmappedNames, s.DirName)
		}
	}
	if len(unmappedNames) > 0 {
		fmt.Fprintf(os.Stderr, "unmapped lenses (%d): %s\n", len(unmappedNames), strings.Join(unmappedNames, ", "))
	}

	if err := writeScorecard(*scorecardPath, allStats, results); err != nil {
		fmt.Fprintf(os.Stderr, "error: write scorecard: %v\n", err)
		os.Exit(4)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", *scorecardPath)

	if regressed {
		fmt.Fprintf(os.Stderr, "\nFAILED: coverage regression detected\n")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "\nPASSED: no coverage regression\n")
}

func parseLensRepo(repoPath string) ([]lensStats, error) {
	entries, err := os.ReadDir(repoPath)
	if err != nil {
		return nil, err
	}

	var result []lensStats
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		dirPath := filepath.Join(repoPath, e.Name())
		jsons, _ := filepath.Glob(filepath.Join(dirPath, "*.json"))
		if len(jsons) == 0 {
			continue
		}

		for _, jp := range jsons {
			stats, err := parseLensFile(jp, e.Name())
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: skip %s: %v\n", jp, err)
				continue
			}
			if stats != nil {
				result = append(result, *stats)
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].DirName < result[j].DirName
	})
	return result, nil
}

func parseLensFile(path, dirName string) (*lensStats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Some upstream lens JSONs contain NaN/Infinity which Go rejects.
	data = nanRe.ReplaceAll(data, []byte(`: null`))

	var l lens
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, err
	}

	var secPillar *pillar
	for i := range l.Pillars {
		id := strings.ToLower(l.Pillars[i].ID)
		name := strings.ToLower(l.Pillars[i].Name)
		if id == "security" || strings.Contains(name, "security") {
			secPillar = &l.Pillars[i]
			break
		}
	}
	if secPillar == nil {
		return nil, nil
	}

	stats := &lensStats{
		DirName:  dirName,
		LensName: l.Name,
	}

	for _, q := range secPillar.Questions {
		for _, c := range q.Choices {
			if strings.HasSuffix(c.ID, "_no") || strings.HasSuffix(c.ID, "_none") {
				continue
			}
			stats.Total++
			if proceduralRe.MatchString(c.Title) {
				stats.Procedural++
			} else {
				stats.Invertible++
			}
		}
	}

	return stats, nil
}

func discoverFixtures(dir string) map[string]bool {
	slugs := make(map[string]bool)
	matches, _ := filepath.Glob(filepath.Join(dir, "snapshot-*-t1.json"))
	for _, m := range matches {
		base := filepath.Base(m)
		slug := strings.TrimPrefix(base, "snapshot-")
		slug = strings.TrimSuffix(slug, "-t1.json")
		t2 := filepath.Join(dir, fmt.Sprintf("snapshot-%s-t2.json", slug))
		if _, err := os.Stat(t2); err == nil {
			slugs[slug] = true
		}
	}
	return slugs
}

func evalFixture(staveBin, fixtureDir, slug, evalTime string) (fixtureResult, error) {
	tmpDir, err := os.MkdirTemp("", "walens-"+slug+"-")
	if err != nil {
		return fixtureResult{}, err
	}
	defer os.RemoveAll(tmpDir)

	for _, suffix := range []string{"t1", "t2"} {
		src := filepath.Join(fixtureDir, fmt.Sprintf("snapshot-%s-%s.json", slug, suffix))
		dst := filepath.Join(tmpDir, fmt.Sprintf("snapshot-%s-%s.json", slug, suffix))
		data, err := os.ReadFile(src)
		if err != nil {
			return fixtureResult{}, err
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return fixtureResult{}, err
		}
	}

	cmd := exec.Command(staveBin, "apply",
		"--observations", tmpDir,
		"--eval-time", evalTime,
		"--format", "json",
	)
	out, err := cmd.Output()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ExitCode() == 3 {
			// exit 3 = violations found = success
		} else if ok {
			return fixtureResult{}, fmt.Errorf("stave apply: %w (stderr: %s)", err, exitErr.Stderr)
		} else {
			return fixtureResult{}, fmt.Errorf("stave apply: %w", err)
		}
	}

	var so staveOutput
	if err := json.Unmarshal(out, &so); err != nil {
		return fixtureResult{}, fmt.Errorf("parse stave output: %w", err)
	}

	controls := make(map[string]bool)
	for _, rs := range so.RiskSignals {
		controls[rs.ControlID] = true
	}

	return fixtureResult{
		Slug:       slug,
		Violations: so.Summary.Violations,
		Controls:   len(controls),
	}, nil
}

func readBaseline(scorecardPath string) map[string]int {
	data, err := os.ReadFile(scorecardPath)
	if err != nil {
		return nil
	}

	baseline := make(map[string]int)
	content := string(data)
	start := strings.Index(content, "<!-- BASELINE")
	end := strings.Index(content, "-->")
	if start < 0 || end < 0 || end <= start {
		return nil
	}

	block := content[start:end]
	for line := range strings.SplitSeq(block, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		slug := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if n, err := strconv.Atoi(val); err == nil {
			baseline[slug] = n
		}
	}
	return baseline
}

func writeScorecard(path string, stats []lensStats, results map[string]fixtureResult) error {
	totalPractices, totalInvertible, totalProcedural := 0, 0, 0
	totalViolations, totalControls := 0, 0
	seenSlugs := make(map[string]bool)

	for _, s := range stats {
		totalPractices += s.Total
		totalInvertible += s.Invertible
		totalProcedural += s.Procedural
	}

	for _, r := range results {
		if !seenSlugs[r.Slug] {
			totalViolations += r.Violations
			totalControls += r.Controls
			seenSlugs[r.Slug] = true
		}
	}

	var b strings.Builder
	now := time.Now().UTC().Format("2006-01-02")

	fmt.Fprintf(&b, "# Well-Architected Lens Coverage Scorecard\n\n")
	fmt.Fprintf(&b, "**Date:** %s\n", now)
	fmt.Fprintf(&b, "**Method:** Automated monthly check — parse WA custom lens JSONs,\n")
	fmt.Fprintf(&b, "run Stave against committed inverted fixtures, compare violation\n")
	fmt.Fprintf(&b, "counts against baseline.\n\n")
	fmt.Fprintf(&b, "**Lenses with Security pillar:** %d\n", len(stats))
	fmt.Fprintf(&b, "**Total Security best practices:** %d\n", totalPractices)
	fmt.Fprintf(&b, "**Invertible (CONFIG + ARCHITECTURAL):** %d\n", totalInvertible)
	fmt.Fprintf(&b, "**Procedural (skipped):** %d\n\n", totalProcedural)
	fmt.Fprintf(&b, "**Stave eval results:** %d risk signals from %d unique controls\n\n", totalViolations, totalControls)

	fmt.Fprintf(&b, "## Violations by Fixture\n\n")
	fmt.Fprintf(&b, "| Fixture | Violations | Unique Controls |\n")
	fmt.Fprintf(&b, "|---|---|---|\n")

	slugs := make([]string, 0, len(results))
	for slug := range results {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)

	for _, slug := range slugs {
		r := results[slug]
		fmt.Fprintf(&b, "| %s | %d | %d |\n", slug, r.Violations, r.Controls)
	}

	fmt.Fprintf(&b, "\n## Lens Practice Counts\n\n")
	fmt.Fprintf(&b, "| Lens | Best Practices | Invertible | Procedural | Fixture |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|\n")

	for _, s := range stats {
		fixture := "—"
		if slug, ok := lensToFixture[s.DirName]; ok {
			fixture = slug
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %s |\n", s.DirName, s.Total, s.Invertible, s.Procedural, fixture)
	}

	fmt.Fprintf(&b, "\n## Lenses Without Fixtures\n\n")
	uncovered := false
	for _, s := range stats {
		if _, ok := lensToFixture[s.DirName]; !ok {
			fmt.Fprintf(&b, "- **%s** (%d invertible practices) — needs fixture generation\n", s.DirName, s.Invertible)
			uncovered = true
		}
	}
	if !uncovered {
		fmt.Fprintf(&b, "All lenses have fixture coverage.\n")
	}

	fmt.Fprintf(&b, "\n<!-- BASELINE (machine-readable — do not edit manually)\n")
	for _, slug := range slugs {
		r := results[slug]
		fmt.Fprintf(&b, "%s: %d\n", slug, r.Violations)
	}
	fmt.Fprintf(&b, "-->\n")

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create scorecard dir: %w", err)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
