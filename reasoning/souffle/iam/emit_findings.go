//go:build ignore

// Command emit_findings — converts Soufflé violation_c + violation_i
// CSV output into Stave PostureFindings JSON.
//
// Reads:
//   <souffle-out>/violation_c.csv
//   <souffle-out>/violation_i.csv
//
// Writes a single JSON document modelling the out.v0.1 finding shape:
//
//   {
//     "schema_version": "out.v0.1",
//     "source": "phase7-cia-tier",
//     "findings": [ ...one per violation row ... ]
//   }
//
// Each finding carries:
//   control_id          — CIA.C.UNAUTHORIZED_READ or
//                          CIA.I.UNAUTHORIZED_WRITE
//   control_name        — human-readable
//   control_severity    — critical (high-sensitivity violation)
//   asset_id            — the principal (the actor)
//   asset_type          — aws_iam_user / aws_iam_role (where known
//                          from has_type; else aws_iam_principal)
//   classification      — state_assertion
//   scope               — compound
//   corpus_reference    — "CIA-derived: <description>"
//   evidence.misconfigurations[0]
//                       — names the resource + action that triggered
//   control_compliance.cia_triad
//                       — "C" or "I"
//
// Usage:
//
//   go run ./reasoning/souffle/iam/emit_findings.go \
//       -souffle-out /tmp/g45-syn-out \
//       -out         /tmp/cia-findings.json
//
// The output is intentionally a SUBSET of the full out.v0.1 schema
// — enough for downstream tooling to consume CIA findings as
// Stave PostureFindings without re-implementing the access-graph
// pipeline. Full integration with stave apply / the FindingDTO
// shape is a follow-up; this commit ships the standalone form.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type options struct {
	souffleOut string
	out        string
}

func parseFlags() *options {
	opts := &options{}
	flag.StringVar(&opts.souffleOut, "souffle-out", "",
		"Path to the Soufflé output directory containing violation_c.csv + violation_i.csv.")
	flag.StringVar(&opts.out, "out", "-",
		"Output path for the CIA findings JSON document. Defaults to stdout.")
	flag.Parse()
	if opts.souffleOut == "" {
		fmt.Fprintln(os.Stderr, "emit_findings: -souffle-out is required")
		os.Exit(2)
	}
	return opts
}

type misconfig struct {
	Property    string `json:"property"`
	ActualValue string `json:"actual_value"`
	Operator    string `json:"operator"`
	UnsafeValue string `json:"unsafe_value"`
}

type evidence struct {
	Misconfigurations []misconfig `json:"misconfigurations"`
}

type finding struct {
	FindingID          string            `json:"finding_id"`
	ControlID          string            `json:"control_id"`
	ControlName        string            `json:"control_name"`
	ControlDescription string            `json:"control_description"`
	ControlSeverity    string            `json:"control_severity"`
	AssetID            string            `json:"asset_id"`
	AssetType          string            `json:"asset_type"`
	AssetVendor        string            `json:"asset_vendor"`
	Classification     string            `json:"classification"`
	Scope              string            `json:"scope"`
	CorpusReference    string            `json:"corpus_reference"`
	Evidence           evidence          `json:"evidence"`
	ControlCompliance  map[string]string `json:"control_compliance"`
}

type document struct {
	SchemaVersion string    `json:"schema_version"`
	Source        string    `json:"source"`
	Findings      []finding `json:"findings"`
}

// confidentialityControl + integrityControl carry the canonical
// metadata for CIA-derived findings. Stable across iterations so
// downstream consumers can join on control_id.
const (
	confidentialityControl     = "CIA.C.UNAUTHORIZED_READ"
	confidentialityControlName = "Confidentiality violation — unauthorized read access to high-sensitivity resource"
	confidentialityDescription = "An unauthorized principal has effective read-equivalent access to a high-sensitivity resource. Derived intensionally from the access-graph reachability analysis (Phase 7 / G4)."

	integrityControl     = "CIA.I.UNAUTHORIZED_WRITE"
	integrityControlName = "Integrity violation — unauthorized write/modify/delete access to high-sensitivity resource"
	integrityDescription = "An unauthorized principal has effective write/modify/delete access to a high-sensitivity resource. Derived intensionally from the access-graph reachability analysis (Phase 7 / G5)."
)

func main() {
	opts := parseFlags()

	// Load principal asset types from has_type.facts if available
	// (one directory above souffleOut, in the extractor's facts
	// directory). Best-effort — when unavailable, asset_type falls
	// back to "aws_iam_principal".
	assetTypes := loadAssetTypes(opts.souffleOut)

	var findings []finding

	cFindings, err := readViolations(filepath.Join(opts.souffleOut, "violation_c.csv"),
		confidentialityControl, confidentialityControlName, confidentialityDescription,
		"C", assetTypes)
	if err != nil {
		fail("read violation_c.csv: %v", err)
	}
	findings = append(findings, cFindings...)

	iFindings, err := readViolations(filepath.Join(opts.souffleOut, "violation_i.csv"),
		integrityControl, integrityControlName, integrityDescription,
		"I", assetTypes)
	if err != nil {
		fail("read violation_i.csv: %v", err)
	}
	findings = append(findings, iFindings...)

	// Stable ordering — sort by (control_id, asset_id,
	// evidence.misconfigurations[0].property).
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].ControlID != findings[j].ControlID {
			return findings[i].ControlID < findings[j].ControlID
		}
		if findings[i].AssetID != findings[j].AssetID {
			return findings[i].AssetID < findings[j].AssetID
		}
		return findings[i].Evidence.Misconfigurations[0].Property <
			findings[j].Evidence.Misconfigurations[0].Property
	})

	doc := document{
		SchemaVersion: "out.v0.1",
		Source:        "phase7-cia-tier",
		Findings:      findings,
	}

	var w io.Writer
	if opts.out == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(opts.out)
		if err != nil {
			fail("create %s: %v", opts.out, err)
		}
		defer f.Close()
		w = f
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		fail("encode JSON: %v", err)
	}

	fmt.Fprintf(os.Stderr, "Emitted %d CIA findings (%d C + %d I) to %s\n",
		len(findings), len(cFindings), len(iFindings), opts.out)
}

func readViolations(path, controlID, controlName, controlDesc, ciaLetter string, assetTypes map[string]string) ([]finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []finding
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		principal := fields[0]
		resource := fields[1]
		action := fields[2]

		// Asset type lookup — best-effort; default to a generic
		// IAM principal type when has_type didn't carry the
		// specific subtype.
		atype := assetTypes[principal]
		if atype == "" {
			atype = "aws_iam_principal"
		}

		// Property path encoding for the misconfiguration:
		// "<action> on <resource>" — descriptive enough for
		// the downstream triage UI to render without
		// re-querying Soufflé.
		propPath := fmt.Sprintf("effective_access.%s.%s", ciaLetter, action)

		// Finding ID = sha256 over the tuple, truncated to 16 chars
		// (consistent with Stave's existing finding_id convention).
		h := sha256.Sum256([]byte(principal + "|" + resource + "|" + action + "|" + controlID))
		fid := "sha256:" + hex.EncodeToString(h[:8])

		out = append(out, finding{
			FindingID:          fid,
			ControlID:          controlID,
			ControlName:        controlName,
			ControlDescription: controlDesc,
			ControlSeverity:    "critical",
			AssetID:            principal,
			AssetType:          atype,
			AssetVendor:        "aws",
			Classification:     "state_assertion",
			Scope:              "compound",
			CorpusReference: fmt.Sprintf(
				"CIA-derived: %s violation via access-graph reachability analysis (principal %s → resource %s via %s)",
				map[string]string{"C": "Confidentiality", "I": "Integrity"}[ciaLetter],
				principal, resource, action),
			Evidence: evidence{
				Misconfigurations: []misconfig{{
					Property:    propPath,
					ActualValue: resource,
					Operator:    "reaches",
					UnsafeValue: resource,
				}},
			},
			ControlCompliance: map[string]string{
				"cia_triad": ciaLetter,
			},
		})
	}
	return out, nil
}

// loadAssetTypes reads has_type.facts (sibling-of-sibling of
// souffleOut — the extractor's facts dir). Best-effort; missing
// file or directory yields an empty map and the caller falls
// back to the generic asset type.
func loadAssetTypes(souffleOut string) map[string]string {
	// Conventional layout: validate.go puts facts at <out>/facts
	// and souffle output at <out>/souffle. So has_type.facts is
	// at <souffle-out>/../facts/has_type.facts.
	parent := filepath.Dir(souffleOut)
	candidates := []string{
		filepath.Join(parent, "facts", "has_type.facts"),
		filepath.Join(parent, "has_type.facts"),
		filepath.Join(souffleOut, "..", "has_type.facts"),
	}
	out := map[string]string{}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			if line == "" {
				continue
			}
			fields := strings.Split(line, "\t")
			if len(fields) < 2 {
				continue
			}
			out[fields[0]] = fields[1]
		}
		return out
	}
	return out
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "emit_findings: "+format+"\n", args...)
	os.Exit(1)
}
