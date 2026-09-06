package stave

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/app/attackpath"
	"github.com/sufield/stave/internal/core/capabilities"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// attackPathAssessment is the minimal subset of out.v0.1 the attack-path
// export reads.
type attackPathAssessment struct {
	CompoundFindings []attackPathCompoundFinding `json:"compound_findings"`
	Findings         []attackPathFinding         `json:"findings"`
}

type attackPathCompoundFinding struct {
	Chain           string   `json:"chain"`
	ControlsFailing []string `json:"controls_failing"`
}

type attackPathFinding struct {
	ControlID   string `json:"control_id"`
	Remediation string `json:"remediation"`
}

// BuildAttackPath builds the attack-path graph — active chain findings,
// directed chain edges (postcondition of A satisfies precondition of B),
// and per-chain control remediation — from a `stave apply` assessment
// (out.v0.1 JSON) and the chain catalog in chainsDir, and renders it in
// the requested format ("json", "dot", or "csv-edges"). now stamps the
// graph; assessmentPath is recorded in it. All failures stay plain
// (exit 4). It is the library entry point behind `stave path`.
func BuildAttackPath(assessmentData []byte, chainsDir, assessmentPath, format string, now time.Time) ([]byte, error) {
	var assessment attackPathAssessment
	if err := json.Unmarshal(assessmentData, &assessment); err != nil {
		return nil, fmt.Errorf("parse assessment: %w", err)
	}

	chains, err := ctlyaml.LoadChains(chainsDir, capabilities.Builtin())
	if err != nil {
		return nil, fmt.Errorf("load chains: %w", err)
	}

	// Build remediation lookup from assessment findings.
	remediationByCtl := make(map[string]string, len(assessment.Findings))
	for _, f := range assessment.Findings {
		if f.Remediation != "" {
			remediationByCtl[f.ControlID] = f.Remediation
		}
	}
	controlLookup := make(map[string]*policy.ControlDefinition)
	for cid, rem := range remediationByCtl {
		controlLookup[cid] = &policy.ControlDefinition{
			ID:          kernel.ControlID(cid),
			Remediation: policy.NewRemediationSpec("", rem, ""),
		}
	}

	var findings []attackpath.ActiveFinding
	for _, cf := range assessment.CompoundFindings {
		var cids []kernel.ControlID
		for _, c := range cf.ControlsFailing {
			cids = append(cids, kernel.ControlID(c))
		}
		findings = append(findings, attackpath.ActiveFinding{
			ChainID:         kernel.ChainID(cf.Chain),
			ControlsFailing: cids,
		})
	}

	graph := attackpath.Build(attackpath.BuildInput{
		GeneratedAt:    now.Format(time.RFC3339),
		AssessmentPath: assessmentPath,
		Chains:         chains,
		Findings:       findings,
		ControlLookup:  controlLookup,
	})

	return renderAttackPath(graph, format)
}

// renderAttackPath renders the graph as JSON, Graphviz DOT, or a CSV edge
// list. There is no default human format — an unknown (or empty) format is
// an error. Split out so it is unit-testable without I/O.
func renderAttackPath(graph *attackpath.Graph, format string) ([]byte, error) {
	var buf bytes.Buffer
	switch format {
	case "json":
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(graph); err != nil {
			return nil, fmt.Errorf("encode json: %w", err)
		}
	case "dot":
		if err := attackpath.WriteDOT(&buf, graph); err != nil {
			return nil, fmt.Errorf("write DOT: %w", err)
		}
	case "csv-edges":
		if err := attackpath.WriteCSVEdges(&buf, graph); err != nil {
			return nil, fmt.Errorf("write CSV edges: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown format %q (valid: json, dot, csv-edges)", format)
	}
	return buf.Bytes(), nil
}
