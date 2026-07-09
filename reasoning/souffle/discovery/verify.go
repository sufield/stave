//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// pathCondition is one Soufflé-emitted condition edge.
type pathCondition struct {
	Principal string
	Target    string
	Key       string
	Value     string
}

// verifyStatus annotates a discovered path.
type verifyStatus struct {
	Status     string   `json:"status"`
	Conflicts  []string `json:"conflicts,omitempty"`
	Conditions int      `json:"conditions"`
	Engine     string   `json:"engine"`
}

func parsePathConditions(souffleOut string) ([]pathCondition, error) {
	lines, err := readCSV(filepath.Join(souffleOut, "path_condition.csv"))
	if err != nil {
		return nil, err
	}
	var out []pathCondition
	for _, cols := range lines {
		if len(cols) < 4 {
			continue
		}
		out = append(out, pathCondition{
			Principal: cols[0],
			Target:    cols[1],
			Key:       cols[2],
			Value:     cols[3],
		})
	}
	return out, nil
}

// edgeKey identifies a role-assumption edge.
type edgeKey struct{ From, To string }

// buildConditionIndex groups conditions by (from→to) edge.
func buildConditionIndex(conds []pathCondition) map[edgeKey][]pathCondition {
	idx := make(map[edgeKey][]pathCondition)
	for _, c := range conds {
		k := edgeKey{c.Principal, c.Target}
		idx[k] = append(idx[k], c)
	}
	return idx
}

// verifyPath checks whether the conditions along a path are satisfiable.
// Uses Z3 SMT solver when available, falls back to contradiction check.
func verifyPath(p discoveredPath, condIdx map[edgeKey][]pathCondition, useZ3 bool) verifyStatus {
	var allConds []pathCondition
	for i := 0; i < len(p.Path)-1; i++ {
		edge := edgeKey{p.Path[i], p.Path[i+1]}
		allConds = append(allConds, condIdx[edge]...)
	}

	if len(allConds) == 0 {
		return verifyStatus{Status: "unconstrained", Engine: "none"}
	}

	if useZ3 {
		return verifyZ3(allConds)
	}
	return verifyContradiction(allConds)
}

// verifyContradiction uses simple same-key conflict detection.
func verifyContradiction(conds []pathCondition) verifyStatus {
	seen := make(map[string]string)
	var conflicts []string
	for _, c := range conds {
		if prev, ok := seen[c.Key]; ok {
			if prev != c.Value {
				conflicts = append(conflicts, fmt.Sprintf("%s: %s≠%s", c.Key, prev, c.Value))
			}
		} else {
			seen[c.Key] = c.Value
		}
	}
	if len(conflicts) > 0 {
		return verifyStatus{
			Status:     "unsatisfiable",
			Conflicts:  conflicts,
			Conditions: len(conds),
			Engine:     "contradiction",
		}
	}
	return verifyStatus{
		Status:     "satisfiable",
		Conditions: len(conds),
		Engine:     "contradiction",
	}
}

// verifyZ3 encodes conditions as SMT-LIB2 and calls Z3 for satisfiability.
func verifyZ3(conds []pathCondition) verifyStatus {
	smt := toSMTLIB2(conds)

	cmd := exec.Command("z3", "-in", "-smt2")
	cmd.Stdin = strings.NewReader(smt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// z3 returns exit 1 for unsat — check stdout
		out := strings.TrimSpace(stdout.String())
		if out == "unsat" {
			return verifyStatus{
				Status:     "unsatisfiable",
				Conditions: len(conds),
				Engine:     "z3",
			}
		}
		// Real error — fall back
		return verifyContradiction(conds)
	}

	out := strings.TrimSpace(stdout.String())
	switch {
	case out == "sat":
		return verifyStatus{
			Status:     "satisfiable",
			Conditions: len(conds),
			Engine:     "z3",
		}
	case out == "unsat":
		return verifyStatus{
			Status:     "unsatisfiable",
			Conditions: len(conds),
			Engine:     "z3",
		}
	default:
		return verifyStatus{
			Status:     "unknown",
			Conditions: len(conds),
			Engine:     "z3",
			Conflicts:  []string{out},
		}
	}
}

// toSMTLIB2 encodes path conditions as an SMT-LIB2 satisfiability problem.
// Each unique condition key becomes a String variable. Each condition
// asserts that the variable equals its value.
func toSMTLIB2(conds []pathCondition) string {
	var b strings.Builder
	b.WriteString("(set-logic QF_S)\n")

	// Collect unique keys and declare them as String constants.
	keys := make(map[string]bool)
	for _, c := range conds {
		keys[c.Key] = true
	}
	for k := range keys {
		fmt.Fprintf(&b, "(declare-const %s String)\n", smtIdent(k))
	}

	// Assert each condition.
	for _, c := range conds {
		fmt.Fprintf(&b, "(assert (= %s %q))\n", smtIdent(c.Key), c.Value)
	}

	b.WriteString("(check-sat)\n")
	return b.String()
}

// smtIdent sanitizes a condition key into a valid SMT-LIB2 identifier.
func smtIdent(key string) string {
	r := strings.NewReplacer(
		":", "_", ".", "_", "/", "_", "-", "_", "*", "_star",
	)
	id := r.Replace(key)
	if id == "" {
		return "_empty"
	}
	// SMT-LIB2 quoted symbol for safety
	return "|" + id + "|"
}

func z3Available() bool {
	_, err := exec.LookPath("z3")
	return err == nil
}

// verifyAll annotates all discovered paths and prints a summary.
func verifyAll(paths []discoveredPath, souffleOut string) map[int]verifyStatus {
	conds, err := parsePathConditions(souffleOut)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not parse path_condition.csv: %v\n", err)
		return nil
	}

	condIdx := buildConditionIndex(conds)

	useZ3 := z3Available()
	if useZ3 {
		fmt.Fprintf(os.Stderr, "  engine: z3 (SMT-LIB2)\n")
	} else {
		fmt.Fprintf(os.Stderr, "  engine: contradiction-check (z3 not found)\n")
	}

	results := make(map[int]verifyStatus, len(paths))
	var sat, unsat, uncon int
	for i, p := range paths {
		v := verifyPath(p, condIdx, useZ3)
		results[i] = v
		switch v.Status {
		case "satisfiable":
			sat++
		case "unsatisfiable":
			unsat++
		case "unconstrained":
			uncon++
		}
	}

	fmt.Fprintf(os.Stderr, "  %d conditions across %d edges\n", len(conds), len(condIdx))
	fmt.Fprintf(os.Stderr, "  paths: %d satisfiable, %d unsatisfiable, %d unconstrained\n", sat, unsat, uncon)

	return results
}
