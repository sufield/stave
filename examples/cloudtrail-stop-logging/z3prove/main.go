// Command z3prove demonstrates Z3-based reasoning about
// CloudTrail object-event coverage gaps. The CEL example at
// the parent main.go detects only `is_logging=false` or
// `is_multi_region_trail=false` — the headline-grabbing case
// of an attacker stopping the trail. This prover detects the
// quieter, more common failure mode: management events are
// logged, but object-level operations on sensitive buckets
// are not.
//
// MITRE ATT&CK T1562.008 — "Disable or Modify Cloud Logs"
// covers both. Most production environments fail at the data-
// event level, not at the trail level: object writes are
// high-volume, costly to log, and so disabled by default.
//
// # Modelling note
//
// Same library/module isolation as the other go-z3 provers in examples/: aclements/go-z3
// has no string theory, so each query enumerates buckets and
// asks Z3 to find a SAT witness over the integer index.
//
// Two queries:
//
//	queryDataEventGap(fix)
//	  Encodes: ∃ bucket b: is_sensitive(b) ∧ ¬covered(b),
//	  where covered means some trail's data_resources
//	  pattern matches b.arn.
//
//	queryWriteWithoutAudit(fix)
//	  Compounds Extension A's exposure with Extension B's gap.
//	  Encodes: ∃ b: write_admitted(developer, "s3:PutObject", b)
//	              ∧ is_sensitive(b)
//	              ∧ ¬covered(b).
//	  Without an IAM principal in the fixture, the prover
//	  reports "no principal — query NA" rather than guessing.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/aclements/go-z3/z3"
)

type bucketWitness struct {
	arn                string
	name               string
	environment        string
	dataClassification string
}

type trailWitness struct {
	name             string
	isLogging        bool
	dataResourceArns []string // S3 object-event coverage prefixes (ARN values from event_selectors)
}

type fixture struct {
	trails  []trailWitness
	buckets []bucketWitness
}

const (
	classConfidential = "confidential"
	classSensitive    = "sensitive"
	classPII          = "pii"
	classFinancial    = "financial"
)

var sensitiveClasses = map[string]bool{
	classConfidential: true,
	classSensitive:    true,
	classPII:          true,
	classFinancial:    true,
}

func isSensitive(b bucketWitness) bool {
	if sensitiveClasses[strings.ToLower(b.dataClassification)] {
		return true
	}
	return strings.EqualFold(b.environment, "production")
}

func main() {
	root, err := exampleRoot()
	if err != nil {
		log.Fatalf("locate example root: %v", err)
	}

	phase := "both"
	if len(os.Args) > 1 {
		phase = os.Args[1]
	}

	ok := true
	if phase == "data-events-before" || phase == "both" {
		ok = runProof(filepath.Join(root, "fixtures/data-events-before/observations"),
			"data-events-before (mgmt logging on, data events off)", true) && ok
	}
	if phase == "both" {
		fmt.Println()
	}
	if phase == "data-events-after" || phase == "both" {
		ok = runProof(filepath.Join(root, "fixtures/data-events-after/observations"),
			"data-events-after  (data events scoped to sensitive buckets)", false) && ok
	}
	if !ok {
		os.Exit(1)
	}
}

func runProof(snapshotsDir, label string, expectGap bool) bool {
	fix, err := loadFixture(snapshotsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] load: %v\n", label, err)
		return false
	}

	fmt.Printf("=== %s ===\n", label)
	fmt.Printf("  trails observed:  %d\n", len(fix.trails))
	for _, t := range fix.trails {
		fmt.Printf("    - %s   is_logging=%v   data_resource_patterns=%d\n",
			t.name, t.isLogging, len(t.dataResourceArns))
		for _, p := range t.dataResourceArns {
			fmt.Printf("        coverage: %s\n", p)
		}
	}
	fmt.Printf("  buckets observed: %d\n", len(fix.buckets))
	for _, b := range fix.buckets {
		fmt.Printf("    - %s   environment=%s   data_classification=%s   sensitive=%v\n",
			b.name, b.environment, b.dataClassification, isSensitive(b))
	}

	q1 := queryDataEventGap(fix)
	fmt.Println()
	fmt.Println("  --- S3 Data Event Logging Gap ---")
	q1.print()

	q2 := queryWriteWithoutAudit(fix, q1)
	fmt.Println()
	fmt.Println("  --- Compound: Write Access + No Audit Trail ---")
	q2.print()

	got := q1.sat
	if got != expectGap {
		fmt.Fprintf(os.Stderr, "  ASSERTION FAILED: expected gap=%v, got gap=%v\n",
			expectGap, got)
		return false
	}
	fmt.Printf("\n  assertion: gap=%v (expected) %s\n", got, "OK")
	return true
}

type verdict struct {
	sat       bool
	witness   string
	rationale string
}

func (v verdict) print() {
	if v.sat {
		fmt.Printf("  verdict: SAT\n")
	} else {
		fmt.Printf("  verdict: UNSAT\n")
	}
	if v.witness != "" {
		fmt.Printf("  witness: %s\n", v.witness)
	}
	if v.rationale != "" {
		fmt.Printf("  rationale: %s\n", v.rationale)
	}
}

// queryDataEventGap asks: ∃ bucket b such that b is sensitive
// and no trail's data_resources covers b.arn?
func queryDataEventGap(fix fixture) verdict {
	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	bucketIdx := ctx.IntConst("bucket")

	var gapHits []int
	for i, b := range fix.buckets {
		if !isSensitive(b) {
			continue
		}
		if !bucketCovered(b.arn, fix.trails) {
			gapHits = append(gapHits, i)
		}
	}

	if len(gapHits) == 0 {
		return verdict{
			sat:       false,
			rationale: "every sensitive bucket is covered by at least one trail's data_resources",
		}
	}

	target := disjunction(ctx, bucketIdx, gapHits, intSort)
	s := z3.NewSolver(ctx)
	s.Assert(target)
	sat, err := s.Check()
	if err != nil || !sat {
		return verdict{sat: false, rationale: "z3 disagreed (unexpected)"}
	}
	m := s.Model()
	v := m.Eval(bucketIdx, true)
	idx, isLit, ok := v.(z3.Int).AsInt64()
	if !ok || !isLit || int(idx) >= len(fix.buckets) {
		return verdict{sat: true, witness: "(witness not extractable)"}
	}
	b := fix.buckets[idx]
	return verdict{
		sat: true,
		witness: fmt.Sprintf("%s   (sensitive=%v, classification=%s, environment=%s, data_event_coverage=NONE)",
			b.arn, isSensitive(b), b.dataClassification, b.environment),
		rationale: fmt.Sprintf("%d of %d sensitive buckets fall outside every trail's data_resources",
			len(gapHits), countSensitive(fix.buckets)),
	}
}

// queryWriteWithoutAudit reports the compound: a sensitive
// bucket that is both writable by some principal AND not
// covered by data events. This example doesn't ship
// IAM principals — when none are observed, the query reports
// the abstract conjunction that the Bybit prover in examples/iam-overpermission-wildcard/
// resolves.
func queryWriteWithoutAudit(fix fixture, gap verdict) verdict {
	ctx := z3.NewContext(nil)
	hasGap := ctx.FromBool(gap.sat)

	// Without an IAM principal in the fixture, the write-access
	// branch is unconstrained — represented as a free Bool.
	// The compound reports SAT iff the gap is real (gap.sat) AND
	// some principal admits writes (assumed when no policies
	// are observed; the iam-overpermission-wildcard Bybit prover discharges this).
	writeAdmitted := ctx.BoolConst("write_admitted_by_some_principal")
	compound := hasGap.And(writeAdmitted)

	s := z3.NewSolver(ctx)
	s.Assert(compound)
	sat, err := s.Check()
	if err != nil {
		return verdict{sat: false, rationale: "z3 error"}
	}
	if !sat {
		return verdict{
			sat:       false,
			rationale: "no logging gap → compound trivially UNSAT",
		}
	}
	return verdict{
		sat:       true,
		witness:   "any principal with s3:PutObject on the gap bucket can modify objects without a CloudTrail data-event record",
		rationale: "this example doesn't enumerate IAM policies; the iam-overpermission-wildcard bybit-pattern prover discharges the write_admitted side of the conjunction on a real fixture",
	}
}

func bucketCovered(bucketArn string, trails []trailWitness) bool {
	for _, t := range trails {
		if !t.isLogging {
			continue
		}
		for _, pattern := range t.dataResourceArns {
			if dataResourceMatches(pattern, bucketArn) {
				return true
			}
		}
	}
	return false
}

// dataResourceMatches replicates AWS CloudTrail's S3 object
// data-resource matching: a pattern ending in `/` matches
// every object in that bucket; an exact ARN matches only
// itself.
func dataResourceMatches(pattern, bucketArn string) bool {
	if strings.HasSuffix(pattern, "/") {
		prefix := strings.TrimSuffix(pattern, "/")
		return prefix == bucketArn || strings.HasPrefix(bucketArn, prefix+"/")
	}
	return pattern == bucketArn
}

func countSensitive(buckets []bucketWitness) int {
	n := 0
	for _, b := range buckets {
		if isSensitive(b) {
			n++
		}
	}
	return n
}

func disjunction(ctx *z3.Context, key z3.Int, indices []int, sort z3.Sort) z3.Bool {
	if len(indices) == 0 {
		return ctx.FromBool(false)
	}
	first := key.Eq(ctx.FromInt(int64(indices[0]), sort).(z3.Int))
	if len(indices) == 1 {
		return first
	}
	rest := make([]z3.Bool, 0, len(indices)-1)
	for _, i := range indices[1:] {
		rest = append(rest, key.Eq(ctx.FromInt(int64(i), sort).(z3.Int)))
	}
	return first.Or(rest...)
}

func loadFixture(snapshotsDir string) (fixture, error) {
	entries, err := os.ReadDir(snapshotsDir)
	if err != nil {
		return fixture{}, fmt.Errorf("read dir %s: %w", snapshotsDir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(snapshotsDir, name))
		if err != nil {
			return fixture{}, err
		}
		var snap struct {
			Assets []struct {
				ID         string `json:"id"`
				Type       string `json:"type"`
				Properties struct {
					Trail struct {
						Name           string `json:"name"`
						IsLogging      bool   `json:"is_logging"`
						EventSelectors []struct {
							DataResources []struct {
								Type   string   `json:"type"`
								Values []string `json:"values"`
							} `json:"data_resources"`
						} `json:"event_selectors"`
					} `json:"trail"`
					Bucket struct {
						Name string            `json:"name"`
						Tags map[string]string `json:"tags"`
					} `json:"bucket"`
				} `json:"properties"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(raw, &snap); err != nil {
			return fixture{}, fmt.Errorf("parse %s: %w", name, err)
		}

		fix := fixture{}
		for _, a := range snap.Assets {
			switch a.Type {
			case "aws_cloudtrail_trail":
				t := trailWitness{
					name:      a.Properties.Trail.Name,
					isLogging: a.Properties.Trail.IsLogging,
				}
				for _, sel := range a.Properties.Trail.EventSelectors {
					for _, dr := range sel.DataResources {
						if dr.Type != "AWS::S3::Object" {
							continue
						}
						t.dataResourceArns = append(t.dataResourceArns, dr.Values...)
					}
				}
				fix.trails = append(fix.trails, t)
			case "aws_s3_bucket":
				fix.buckets = append(fix.buckets, bucketWitness{
					arn:                a.ID,
					name:               a.Properties.Bucket.Name,
					environment:        a.Properties.Bucket.Tags["environment"],
					dataClassification: a.Properties.Bucket.Tags["data_classification"],
				})
			}
		}
		if len(fix.buckets) > 0 || len(fix.trails) > 0 {
			return fix, nil
		}
	}
	return fixture{}, fmt.Errorf("no trail or bucket assets found in %s", snapshotsDir)
}

func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(filepath.Dir(file)), nil
}
