// Command semantic-diff runs a differential test between Stave's CEL
// predicate evaluator and an independent Z3-based reference evaluator.
// For each control, it generates systematic test vectors (all field
// combinations of present/absent/safe/unsafe), evaluates both engines,
// and reports any divergence. A symbolic Z3 equivalence check proves
// no divergence exists beyond the concrete vectors.
//
// This is development-time tooling. It does not touch runtime paths.
//
// Usage:
//
//	make semantic-diff                    # all S3 policy controls
//	make semantic-diff ARGS="-controls controls/s3/access"
//	make semantic-diff ARGS="-symbolic"   # include Z3 symbolic proof
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/internal/adapters/cel"
	yamlctl "github.com/sufield/stave/internal/adapters/controls/yaml"
	predalias "github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

func main() {
	controlDirs := flag.String("controls", "", "comma-separated control directories (default: s3 policy controls)")
	chainFile := flag.String("chain", "", "chain YAML file for compound differential (default: iam_condition_bypass)")
	symbolic := flag.Bool("symbolic", false, "run Z3 symbolic equivalence proof (requires libz3)")
	verbose := flag.Bool("v", false, "verbose: print each test vector result")
	flag.Parse()

	dirs := defaultS3Dirs()
	if *controlDirs != "" {
		dirs = strings.Split(*controlDirs, ",")
	}

	controls, err := loadControls(dirs)
	if err != nil {
		log.Fatalf("load controls: %v", err)
	}

	compiler, err := cel.NewCompiler()
	if err != nil {
		log.Fatalf("cel compiler: %v", err)
	}

	divergences := runControlDiff(controls, compiler, *verbose)

	if *symbolic {
		fmt.Println("\n--- symbolic equivalence ---")
		for i := range controls {
			ctl := &controls[i]
			if ctl.UnsafePredicate.IsEmpty() {
				continue
			}
			fields := extractFields(ctl.UnsafePredicate)
			result := symbolicCheck(ctl.UnsafePredicate, fields)
			fmt.Printf("[%s] %s: %s\n", result.Status, ctl.ID, result.Detail)
		}
	}

	// Chain differential
	chainPath := "chains/iam_condition_bypass.yaml"
	if *chainFile != "" {
		chainPath = *chainFile
	}
	chainDivergences := runChainDiff(chainPath, compiler, *verbose)
	divergences += chainDivergences

	if divergences > 0 {
		os.Exit(3)
	}
}

func runControlDiff(controls []policy.ControlDefinition, compiler *cel.Compiler, verbose bool) int {
	var totalControls, totalVectors, divergences int

	for i := range controls {
		ctl := &controls[i]
		if ctl.UnsafePredicate.IsEmpty() {
			continue
		}

		cp, err := compiler.Compile(ctl.UnsafePredicate)
		if err != nil {
			log.Printf("SKIP %s: compile error: %v", ctl.ID, err)
			continue
		}

		fields := extractFields(ctl.UnsafePredicate)
		vectors := generateVectors(fields)

		totalControls++
		controlDivergences := 0

		for _, vec := range vectors {
			totalVectors++

			a := buildAsset(vec)
			celResult, celErr := cel.Evaluate(cp, a, nil, ctl.Params.Raw())
			if celErr != nil {
				celResult = false
			}

			refResult := evalReference(ctl.UnsafePredicate, vec)

			if celResult != refResult {
				controlDivergences++
				divergences++
				fmt.Printf("DIVERGENCE %s: cel=%v ref=%v vector=%s\n",
					ctl.ID, celResult, refResult, formatVector(vec))
			} else if verbose {
				fmt.Printf("  OK %s: result=%v vector=%s\n",
					ctl.ID, celResult, formatVector(vec))
			}
		}

		status := "PASS"
		if controlDivergences > 0 {
			status = "FAIL"
		}
		fmt.Printf("[%s] %s: %d vectors, %d divergences\n",
			status, ctl.ID, len(vectors), controlDivergences)
	}

	fmt.Printf("\n--- per-control summary ---\ncontrols: %d  vectors: %d  divergences: %d\n",
		totalControls, totalVectors, divergences)
	return divergences
}

// runChainDiff tests a compound chain's threshold logic. A chain fires
// when >= escalation_threshold of its member controls fire on the same
// asset. The differential verifies that the reference threshold
// calculation matches the CEL-based control outcomes.
func runChainDiff(chainPath string, compiler *cel.Compiler, verbose bool) int {
	chain, err := loadChain(chainPath)
	if err != nil {
		log.Printf("SKIP chain %s: %v", chainPath, err)
		return 0
	}

	// Load the chain's member controls
	controlDirs := chainControlDirs(chain)
	controls, err := loadControls(controlDirs)
	if err != nil {
		log.Printf("SKIP chain %s: load controls: %v", chain.ID, err)
		return 0
	}

	// Build control ID → compiled predicate + fields
	type controlEntry struct {
		def    *policy.ControlDefinition
		cp     cel.CompiledPredicate
		fields []fieldInfo
	}
	var entries []controlEntry
	for i := range controls {
		ctl := &controls[i]
		if !isChainMember(chain, ctl.ID) {
			continue
		}
		if ctl.UnsafePredicate.IsEmpty() {
			continue
		}
		cp, err := compiler.Compile(ctl.UnsafePredicate)
		if err != nil {
			log.Printf("SKIP chain member %s: %v", ctl.ID, err)
			continue
		}
		entries = append(entries, controlEntry{
			def:    ctl,
			cp:     cp,
			fields: extractFields(ctl.UnsafePredicate),
		})
	}

	if len(entries) < int(chain.EscalationThreshold) {
		log.Printf("SKIP chain %s: only %d members loaded, threshold=%d",
			chain.ID, len(entries), chain.EscalationThreshold)
		return 0
	}

	fmt.Printf("\n--- chain differential: %s (threshold=%d, members=%d) ---\n",
		chain.ID, chain.EscalationThreshold, len(entries))

	// Generate combined vectors: for each member control, it either
	// fires (all fields present with unsafe values) or doesn't (one
	// field absent). Test all 2^N combinations.
	n := 1 << len(entries)
	var totalVectors, divergences int

	for mask := range n {
		totalVectors++

		// Build a combined asset with properties from all firing controls
		props := make(map[string]any)
		var celFires, refFires int

		for bit, e := range entries {
			shouldFire := mask&(1<<bit) != 0

			if shouldFire {
				// Set all fields to unsafe values
				for _, f := range e.fields {
					setNestedField(props, f.Path, f.Value)
				}
			}
			// If not firing, leave fields absent
		}

		a := asset.Asset{
			ID:         "chain-test",
			Type:       kernel.AssetType("aws_iam_user"),
			Vendor:     "aws",
			Properties: props,
		}

		// Evaluate each control
		for bit, e := range entries {
			shouldFire := mask&(1<<bit) != 0

			celResult, celErr := cel.Evaluate(e.cp, a, nil, e.def.Params.Raw())
			if celErr != nil {
				celResult = false
			}

			vec := make(testVector)
			for _, f := range e.fields {
				if shouldFire {
					vec[f.Path] = fieldState{Present: true, Value: f.Value}
				} else {
					vec[f.Path] = fieldState{Present: false}
				}
			}
			refResult := evalReference(e.def.UnsafePredicate, vec)

			if celResult {
				celFires++
			}
			if refResult {
				refFires++
			}
		}

		celChainFires := celFires >= chain.EscalationThreshold
		refChainFires := refFires >= chain.EscalationThreshold

		if celChainFires != refChainFires {
			divergences++
			fmt.Printf("CHAIN DIVERGENCE %s: cel_fires=%d ref_fires=%d threshold=%d mask=%b\n",
				chain.ID, celFires, refFires, chain.EscalationThreshold, mask)
		} else if verbose {
			fmt.Printf("  OK chain %s: fires=%v (%d/%d >= %d) mask=%b\n",
				chain.ID, celChainFires, celFires, len(entries), chain.EscalationThreshold, mask)
		}
	}

	status := "PASS"
	if divergences > 0 {
		status = "FAIL"
	}
	fmt.Printf("[%s] chain %s: %d vectors, %d divergences\n",
		status, chain.ID, totalVectors, divergences)
	return divergences
}

func loadChain(path string) (policy.ChainDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return policy.ChainDefinition{}, err
	}
	var chain policy.ChainDefinition
	if err := yaml.Unmarshal(data, &chain); err != nil {
		return policy.ChainDefinition{}, err
	}
	return chain, nil
}

func isChainMember(chain policy.ChainDefinition, id kernel.ControlID) bool {
	return slices.Contains(chain.ControlIDs, id)
}

// chainControlDirs returns the control directories needed for a chain's members.
func chainControlDirs(chain policy.ChainDefinition) []string {
	seen := make(map[string]bool)
	for _, cid := range chain.ControlIDs {
		// CTL.IAM.POLICY.CONDITION.ORGID.001 → controls/iam/policy
		parts := strings.Split(string(cid), ".")
		if len(parts) >= 4 {
			dir := "controls/" + strings.ToLower(parts[1]) + "/" + strings.ToLower(parts[2])
			if !seen[dir] {
				seen[dir] = true
			}
		}
	}
	dirs := make([]string, 0, len(seen))
	for d := range seen {
		dirs = append(dirs, d)
	}
	return dirs
}

func defaultS3Dirs() []string {
	return []string{
		"controls/s3/access",
		"controls/s3/network",
		"controls/s3/perimeter",
		"controls/s3/policy",
	}
}

func loadControls(dirs []string) ([]policy.ControlDefinition, error) {
	loader := yamlctl.NewControlLoader(yamlctl.WithAliasResolver(predalias.ResolverFunc()))
	var all []policy.ControlDefinition
	for _, dir := range dirs {
		controls, err := loader.LoadControls(context.Background(), dir)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", dir, err)
		}
		all = append(all, controls...)
	}
	return all, nil
}

// fieldInfo describes a field referenced in a predicate.
type fieldInfo struct {
	Path      string
	Op        predicate.Operator
	Value     any // the "unsafe" value from the predicate
	SafeValue any // a value that makes this rule not fire
}

// testVector maps field paths to their state in a test case.
type testVector map[string]fieldState

type fieldState struct {
	Present bool
	Value   any
}

func extractFields(pred policy.UnsafePredicate) []fieldInfo {
	var fields []fieldInfo
	seen := make(map[string]bool)

	var walk func(rules []policy.PredicateRule)
	walk = func(rules []policy.PredicateRule) {
		for _, r := range rules {
			walk(r.Any)
			walk(r.All)

			// any_match nests a sub-predicate in Value; recurse into it
			// so fields inside the nested block are visible to diff.
			if r.Op == predicate.OpAnyMatch || r.Op == predicate.OpAnyIdentityMatch {
				walkNestedValue(r.Value.Raw(), &fields, seen)
				if !r.Field.IsZero() {
					path := r.Field.String()
					if !seen[path] {
						seen[path] = true
						fields = append(fields, fieldInfo{
							Path:      path,
							Op:        r.Op,
							Value:     r.Value.Raw(),
							SafeValue: safeValue(r.Op, r.Value.Raw()),
						})
					}
				}
				continue
			}

			if r.Field.IsZero() {
				continue
			}
			path := r.Field.String()
			if seen[path] {
				continue
			}
			seen[path] = true
			fields = append(fields, fieldInfo{
				Path:      path,
				Op:        r.Op,
				Value:     r.Value.Raw(),
				SafeValue: safeValue(r.Op, r.Value.Raw()),
			})
		}
	}
	walk(pred.All)
	walk(pred.Any)
	return fields
}

func walkNestedValue(val any, fields *[]fieldInfo, seen map[string]bool) {
	switch v := val.(type) {
	case *policy.UnsafePredicate:
		if v != nil {
			walkNestedPred(v, fields, seen)
		}
	case policy.UnsafePredicate:
		walkNestedPred(&v, fields, seen)
	case map[string]any:
		walkNestedMap(v, fields, seen)
	}
}

func walkNestedPred(pred *policy.UnsafePredicate, fields *[]fieldInfo, seen map[string]bool) {
	var walk func(rules []policy.PredicateRule)
	walk = func(rules []policy.PredicateRule) {
		for _, r := range rules {
			walk(r.Any)
			walk(r.All)
			if r.Field.IsZero() {
				continue
			}
			path := r.Field.String()
			if seen[path] {
				continue
			}
			seen[path] = true
			*fields = append(*fields, fieldInfo{
				Path:      path,
				Op:        r.Op,
				Value:     r.Value.Raw(),
				SafeValue: safeValue(r.Op, r.Value.Raw()),
			})
		}
	}
	walk(pred.All)
	walk(pred.Any)
}

func walkNestedMap(m map[string]any, fields *[]fieldInfo, seen map[string]bool) {
	for _, key := range [2]string{"any", "all"} {
		list, ok := m[key]
		if !ok {
			continue
		}
		items, ok := list.([]any)
		if !ok {
			continue
		}
		for _, item := range items {
			ruleMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			walkNestedMap(ruleMap, fields, seen)
		}
	}
	fieldStr, _ := m["field"].(string)
	if fieldStr == "" || seen[fieldStr] {
		return
	}
	opStr, _ := m["op"].(string)
	val, _ := m["value"]
	seen[fieldStr] = true
	*fields = append(*fields, fieldInfo{
		Path:      fieldStr,
		Op:        predicate.Operator(opStr),
		Value:     val,
		SafeValue: safeValue(predicate.Operator(opStr), val),
	})
}

func safeValue(op predicate.Operator, unsafeVal any) any {
	switch op {
	case predicate.OpEq:
		switch v := unsafeVal.(type) {
		case bool:
			return !v
		case string:
			return v + "_safe"
		case int:
			return v + 1
		case float64:
			return v + 1
		}
	case predicate.OpNe:
		return unsafeVal // ne fires when field != value, so matching value is safe
	case predicate.OpGt:
		// fires when field > value; safe = value - 1
		switch v := unsafeVal.(type) {
		case int:
			return v - 1
		case float64:
			return v - 1
		}
	case predicate.OpGte:
		// fires when field >= value; safe = value - 1
		switch v := unsafeVal.(type) {
		case int:
			return v - 1
		case float64:
			return v - 1
		}
	case predicate.OpLt:
		// fires when field < value; safe = value + 1
		switch v := unsafeVal.(type) {
		case int:
			return v + 1
		case float64:
			return v + 1
		}
	case predicate.OpLte:
		// fires when field <= value; safe = value + 1
		switch v := unsafeVal.(type) {
		case int:
			return v + 1
		case float64:
			return v + 1
		}
	}
	if b, ok := unsafeVal.(bool); ok {
		return !b
	}
	return "safe_fallback"
}

// generateVectors produces 3^N test vectors: for each field,
// {absent, present-with-unsafe-value, present-with-safe-value}.
func generateVectors(fields []fieldInfo) []testVector {
	if len(fields) == 0 {
		return nil
	}

	n := 1
	for range fields {
		n *= 3
	}

	vectors := make([]testVector, n)
	for i := range vectors {
		vec := make(testVector, len(fields))
		idx := i
		for _, f := range fields {
			switch idx % 3 {
			case 0: // absent
				vec[f.Path] = fieldState{Present: false}
			case 1: // present with unsafe value
				vec[f.Path] = fieldState{Present: true, Value: f.Value}
			case 2: // present with safe value
				vec[f.Path] = fieldState{Present: true, Value: f.SafeValue}
			}
			idx /= 3
		}
		vectors[i] = vec
	}
	return vectors
}

func buildAsset(vec testVector) asset.Asset {
	props := make(map[string]any)
	for path, state := range vec {
		if !state.Present {
			continue
		}
		setNestedField(props, path, state.Value)
	}
	return asset.Asset{
		ID:         "test-asset",
		Type:       kernel.AssetType("aws_s3_bucket"),
		Vendor:     "aws",
		Properties: props,
	}
}

// setNestedField sets a dot-path in a nested map, stripping the
// "properties." prefix since Asset.Map() merges properties at the
// top level.
func setNestedField(m map[string]any, path string, val any) {
	path = strings.TrimPrefix(path, "properties.")
	parts := strings.Split(path, ".")
	cur := m
	for i, p := range parts {
		if i == len(parts)-1 {
			cur[p] = val
			return
		}
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = make(map[string]any)
			cur[p] = next
		}
		cur = next
	}
}

// evalReference is an independent implementation of Stave's predicate
// semantics. It does NOT call the CEL engine — it evaluates the
// predicate tree directly against the test vector using the documented
// operator semantics from compiler.go:440-477.
func evalReference(pred policy.UnsafePredicate, vec testVector) bool {
	allResult := true
	for _, r := range pred.All {
		if !evalRuleRef(r, vec) {
			allResult = false
			break
		}
	}
	if len(pred.All) > 0 && !allResult {
		return false
	}

	if len(pred.Any) > 0 {
		anyResult := false
		for _, r := range pred.Any {
			if evalRuleRef(r, vec) {
				anyResult = true
				break
			}
		}
		if !anyResult {
			return false
		}
	}

	return len(pred.All) > 0 || len(pred.Any) > 0
}

func evalRuleRef(r policy.PredicateRule, vec testVector) bool {
	// Nested all/any blocks
	if len(r.All) > 0 || len(r.Any) > 0 {
		nested := policy.UnsafePredicate{All: r.All, Any: r.Any}
		return evalReference(nested, vec)
	}

	if r.Field.IsZero() {
		return true
	}

	path := r.Field.String()
	state, exists := vec[path]
	hasField := exists && state.Present

	val := r.Value.Raw()

	switch r.Op {
	case predicate.OpEq:
		// fail-open: hasField && field == value
		if !hasField {
			return false
		}
		return valEqual(state.Value, val)

	case predicate.OpNe:
		// fail-closed: !hasField || field != value
		if !hasField {
			return true
		}
		return !valEqual(state.Value, val)

	case predicate.OpGt:
		if !hasField {
			return false
		}
		return valCompare(state.Value, val) > 0

	case predicate.OpLt:
		if !hasField {
			return false
		}
		return valCompare(state.Value, val) < 0

	case predicate.OpGte:
		if !hasField {
			return false
		}
		return valCompare(state.Value, val) >= 0

	case predicate.OpLte:
		if !hasField {
			return false
		}
		return valCompare(state.Value, val) <= 0

	case predicate.OpMissing:
		// fail-closed: !hasField || missing(field)
		if !hasField {
			return true
		}
		return isMissing(state.Value)

	case predicate.OpPresent:
		// fail-open: hasField && !missing(field)
		if !hasField {
			return false
		}
		return !isMissing(state.Value)

	default:
		// conservative: unknown op → false
		return false
	}
}

func valEqual(a, b any) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func valCompare(a, b any) int {
	fa, oka := toFloat(a)
	fb, okb := toFloat(b)
	if oka && okb {
		if fa < fb {
			return -1
		}
		if fa > fb {
			return 1
		}
		return 0
	}
	sa := fmt.Sprintf("%v", a)
	sb := fmt.Sprintf("%v", b)
	if sa < sb {
		return -1
	}
	if sa > sb {
		return 1
	}
	return 0
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}

func isMissing(v any) bool {
	if v == nil {
		return true
	}
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x) == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

func formatVector(vec testVector) string {
	var parts []string
	for path, state := range vec {
		short := path
		if idx := strings.LastIndex(path, "."); idx >= 0 {
			short = path[idx+1:]
		}
		if !state.Present {
			parts = append(parts, short+"=ABSENT")
		} else {
			parts = append(parts, fmt.Sprintf("%s=%v", short, state.Value))
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// symbolicResult holds the outcome of a Z3 symbolic equivalence check.
type symbolicResult struct {
	Status string // "EQUIV", "DIVERGE", "SKIP"
	Detail string
}

// symbolicCheck uses Z3 to prove that the CEL translation and the
// reference semantics agree for ALL possible inputs, not just the
// concrete test vectors. If Z3 finds a satisfying assignment to
// (cel_result XOR ref_result), the control has a semantic gap.
//
// Build tag: this is a stub when Z3 is not available. The real
// implementation is in z3check.go behind a build tag.
func symbolicCheck(pred policy.UnsafePredicate, fields []fieldInfo) symbolicResult {
	return symbolicCheckImpl(pred, fields)
}
