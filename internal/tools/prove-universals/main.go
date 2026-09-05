// prove-universals grounds obs.v0.1 observations into SMT-LIB formulas
// and runs Z3 to verify universal security statements (Direction 1 of
// Adam's bidirectional architecture).
//
// For each universal U26–U33:
//  1. Read the .smt2 formula
//  2. Ground matching observation assets into SMT-LIB assertions
//  3. Close the universe (finite domain)
//  4. Run Z3 subprocess, parse sat/unsat
//
// sat = violation exists (formula finds a counterexample)
// unsat = universal holds for this snapshot
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

type asset struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties"`
}

type snapshot struct {
	Assets []asset `json:"assets"`
}

type grounded struct {
	name  string
	preds map[string]bool
}

type universal struct {
	id    string
	file  string
	sort  string
	preds []string
	match func([]asset) []grounded
}

var defs = []universal{
	{"U26", "u26-service-logging.smt2", "Resource",
		[]string{"generates_security_events", "logging_enabled"}, matchU26},
	{"U27", "u27-endpoint-authentication.smt2", "Endpoint",
		[]string{"accepts_requests", "intent_public", "requires_auth"}, matchU27},
	{"U28", "u28-deletion-protection.smt2", "Resource",
		[]string{"stores_data", "supports_deletion_protection", "deletion_protected"}, matchU28},
	{"U29", "u29-backup-configured.smt2", "Resource",
		[]string{"stores_data", "has_backup"}, matchU29},
	{"U30", "u30-no-plaintext-secrets.smt2", "Config",
		[]string{"has_credential_field", "references_secret_manager"}, matchU30},
	{"U31", "u31-version-currency.smt2", "Resource",
		[]string{"has_managed_version", "version_deprecated", "version_eol"}, matchU31},
	{"U32", "u32-imdsv2-enforced.smt2", "ComputeResource",
		[]string{"has_metadata_endpoint", "enforces_imdsv2"}, matchU32},
	{"U33", "u33-security-service-enabled.smt2", "DetectionService",
		[]string{"in_required_services", "detection_enabled"}, matchU33},
}

// --- Grounding functions ---

func matchU26(assets []asset) []grounded {
	var out []grounded
	for _, a := range assets {
		switch a.Type {
		case "aws_s3_bucket":
			out = append(out, grounded{smtName(a.ID), map[string]bool{
				"generates_security_events": true,
				"logging_enabled":           getBool(a.Properties, "storage", "logging", "enabled"),
			}})
		case "aws_lambda_function":
			out = append(out, grounded{smtName(a.ID), map[string]bool{
				"generates_security_events": true,
				"logging_enabled":           getBool(a.Properties, "compute", "logging", "log_group_exists"),
			}})
		}
	}
	return out
}

func matchU27(assets []asset) []grounded {
	var out []grounded
	for _, a := range assets {
		if a.Type != "aws_lambda_function" {
			continue
		}
		if getMap(a.Properties, "compute", "function_url") == nil {
			continue
		}
		out = append(out, grounded{smtName(a.ID), map[string]bool{
			"accepts_requests": true,
			"intent_public":    false,
			"requires_auth":    !getBool(a.Properties, "compute", "function_url", "auth_type_none"),
		}})
	}
	return out
}

func matchU28(assets []asset) []grounded {
	var out []grounded
	for _, a := range assets {
		if a.Type != "aws_dynamodb_table" {
			continue
		}
		out = append(out, grounded{smtName(a.ID), map[string]bool{
			"stores_data":                  true,
			"supports_deletion_protection": true,
			"deletion_protected":           getBool(a.Properties, "database", "deletion_protection"),
		}})
	}
	return out
}

func matchU29(assets []asset) []grounded {
	var out []grounded
	for _, a := range assets {
		if a.Type != "aws_dynamodb_table" {
			continue
		}
		out = append(out, grounded{smtName(a.ID), map[string]bool{
			"stores_data": true,
			"has_backup":  getBool(a.Properties, "database", "pitr_enabled"),
		}})
	}
	return out
}

func matchU30(assets []asset) []grounded {
	var out []grounded
	for _, a := range assets {
		if a.Type != "aws_lambda_function" {
			continue
		}
		if getMap(a.Properties, "compute", "env") == nil {
			continue
		}
		out = append(out, grounded{smtName(a.ID), map[string]bool{
			"has_credential_field":      true,
			"references_secret_manager": getBool(a.Properties, "compute", "env", "kms_encrypted"),
		}})
	}
	return out
}

func matchU31(assets []asset) []grounded {
	var out []grounded
	for _, a := range assets {
		if a.Type != "aws_glue_job" {
			continue
		}
		out = append(out, grounded{smtName(a.ID), map[string]bool{
			"has_managed_version": true,
			"version_deprecated":  getBool(a.Properties, "compute", "version", "is_outdated"),
			"version_eol":         false,
		}})
	}
	return out
}

func matchU32(assets []asset) []grounded {
	var out []grounded
	for _, a := range assets {
		if a.Type != "aws_ec2_instance" {
			continue
		}
		out = append(out, grounded{smtName(a.ID), map[string]bool{
			"has_metadata_endpoint": true,
			"enforces_imdsv2":       getBool(a.Properties, "compute", "network", "imdsv2_required"),
		}})
	}
	return out
}

func matchU33(assets []asset) []grounded {
	var out []grounded
	for _, a := range assets {
		switch a.Type {
		case "aws_guardduty_detector":
			out = append(out, grounded{smtName(a.ID), map[string]bool{
				"in_required_services": true,
				"detection_enabled":    getBool(a.Properties, "threat_detection", "enabled"),
			}})
		case "aws_config_recorder":
			out = append(out, grounded{smtName(a.ID), map[string]bool{
				"in_required_services": true,
				"detection_enabled":    getBool(a.Properties, "compliance", "recording_enabled"),
			}})
		}
	}
	return out
}

// --- Property access ---

func getBool(props map[string]any, path ...string) bool {
	cur := props
	for i, key := range path {
		v, ok := cur[key]
		if !ok {
			return false
		}
		if i == len(path)-1 {
			b, _ := v.(bool)
			return b
		}
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		cur = m
	}
	return false
}

func getMap(props map[string]any, path ...string) map[string]any {
	cur := props
	for _, key := range path {
		v, ok := cur[key]
		if !ok {
			return nil
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		cur = m
	}
	return cur
}

var nonAlpha = regexp.MustCompile(`[^a-zA-Z0-9]`)

func smtName(id string) string {
	s := nonAlpha.ReplaceAllString(id, "_")
	if len(s) > 50 {
		s = s[len(s)-50:]
	}
	return "c_" + s
}

// --- SMT-LIB generation ---

func generateGrounding(sortName string, preds []string, gs []grounded) string {
	var buf strings.Builder

	if len(gs) == 0 {
		// ponytail: closed world with no elements — assert precondition false
		fmt.Fprintf(&buf, "; no %s assets — precondition false for all\n", sortName)
		fmt.Fprintf(&buf, "(assert (forall ((x %s)) (not (%s x))))\n", sortName, preds[0])
		return buf.String()
	}

	for _, g := range gs {
		fmt.Fprintf(&buf, "(declare-const %s %s)\n", g.name, sortName)
	}

	if len(gs) > 1 {
		names := make([]string, len(gs))
		for i, g := range gs {
			names[i] = g.name
		}
		fmt.Fprintf(&buf, "(assert (distinct %s))\n", strings.Join(names, " "))
	}

	// Close universe — every element of the sort equals one of the constants
	var clauses []string
	for _, g := range gs {
		clauses = append(clauses, fmt.Sprintf("(= x %s)", g.name))
	}
	var closure string
	if len(clauses) == 1 {
		closure = clauses[0]
	} else {
		closure = fmt.Sprintf("(or %s)", strings.Join(clauses, " "))
	}
	fmt.Fprintf(&buf, "(assert (forall ((x %s)) %s))\n", sortName, closure)

	for _, g := range gs {
		for _, pred := range preds {
			val, ok := g.preds[pred]
			if !ok {
				continue
			}
			if val {
				fmt.Fprintf(&buf, "(assert (%s %s))\n", pred, g.name)
			} else {
				fmt.Fprintf(&buf, "(assert (not (%s %s)))\n", pred, g.name)
			}
		}
	}

	return buf.String()
}

func insertGrounding(formula, grounding string) string {
	const marker = "(push 1)"
	idx := strings.Index(formula, marker)
	if idx == -1 {
		return formula
	}
	return formula[:idx] + grounding + "\n" + formula[idx:]
}

// --- Z3 subprocess ---

func runZ3(formula string) (result, output string) {
	tmp, err := os.CreateTemp("", "prove-*.smt2")
	if err != nil {
		return "error", err.Error()
	}
	defer os.Remove(tmp.Name())
	fmt.Fprint(tmp, formula)
	tmp.Close()

	cmd := exec.Command("z3", tmp.Name())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run()

	out := strings.TrimSpace(stdout.String())
	lines := strings.Split(out, "\n")
	for _, line := range slices.Backward(lines) {
		line := strings.TrimSpace(line)
		switch line {
		case "sat", "unsat", "unknown":
			return line, out
		}
	}
	return "error", out + "\n" + stderr.String()
}

// --- Observation loading ---

func loadAssets(dir string) []asset {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		fmt.Fprintf(os.Stderr, "no observation files in %s\n", dir)
		os.Exit(2)
	}

	var all []asset
	seen := map[string]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", f, err)
			os.Exit(4)
		}
		var snap snapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			fmt.Fprintf(os.Stderr, "parse %s: %v\n", f, err)
			os.Exit(4)
		}
		for _, a := range snap.Assets {
			if !seen[a.ID] {
				all = append(all, a)
				seen[a.ID] = true
			}
		}
	}
	return all
}

func main() {
	obsDir := flag.String("observations", "", "observation snapshots directory")
	formulaDir := flag.String("formulas", "data/universals", "SMT-LIB formula directory")
	verbose := flag.Bool("v", false, "show grounded SMT-LIB")
	flag.Parse()

	if *obsDir == "" {
		fmt.Fprintln(os.Stderr, "usage: prove-universals --observations <dir>")
		os.Exit(2)
	}

	if _, err := exec.LookPath("z3"); err != nil {
		fmt.Fprintln(os.Stderr, "z3 not found in PATH — install with: apt install z3")
		os.Exit(4)
	}

	assets := loadAssets(*obsDir)
	fmt.Printf("Loaded %d assets from %s\n\n", len(assets), *obsDir)

	pass, fail := 0, 0
	for _, u := range defs {
		formulaPath := filepath.Join(*formulaDir, u.file)
		formulaContent, err := os.ReadFile(formulaPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read formula %s: %v\n", formulaPath, err)
			os.Exit(4)
		}

		gs := u.match(assets)
		grounding := generateGrounding(u.sort, u.preds, gs)
		formula := insertGrounding(string(formulaContent), grounding)

		if *verbose {
			fmt.Printf("--- %s grounding ---\n%s\n", u.id, grounding)
		}

		result, output := runZ3(formula)
		switch result {
		case "sat", "unsat":
			pass++
		default:
			fail++
		}

		label := "violation"
		if result == "unsat" {
			label = "holds"
		} else if result != "sat" {
			label = result
		}

		vacuous := ""
		if len(gs) == 0 && result == "unsat" {
			vacuous = " (vacuous)"
		}

		fmt.Printf("  %-4s  %-6s  %-10s  grounded=%d%s\n", u.id, result, label, len(gs), vacuous)

		if *verbose && result != "sat" && result != "unsat" {
			fmt.Printf("    z3 output: %s\n", output)
		}
	}

	fmt.Printf("\n%d/%d formulas evaluated successfully\n", pass, pass+fail)
	if fail > 0 {
		os.Exit(1)
	}
}
