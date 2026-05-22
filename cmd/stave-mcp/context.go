package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/sufield/stave/pkg/stave"
)

// contextArgs is the schema for stave.context — the drill-down tool.
// The model calls it with a {type, id} to get detail about one
// finding, asset, chain, requirement, or framework. It is the
// model-facing endpoint that a UI selection event maps onto (see the
// event bridge in the dashboard/scorecard/chains templates), but it is
// equally useful when a user just asks about a specific item.
type contextArgs struct {
	Type              string `json:"type"`
	ID                string `json:"id"`
	Observations      string `json:"observations,omitempty"`
	Controls          string `json:"controls,omitempty"`
	Chains            string `json:"chains,omitempty"`
	Framework         string `json:"framework,omitempty"`
	AllowUnknownInput bool   `json:"allow_unknown_input,omitempty"`
}

// runContextTool routes a drill-down request by type. Returns an
// unwrapped value; the dispatcher wraps it in the tool-result envelope.
func runContextTool(ctx context.Context, args contextArgs) (any, error) {
	kind := strings.ToLower(strings.TrimSpace(args.Type))
	if kind == "" || strings.TrimSpace(args.ID) == "" {
		return nil, errors.New("type and id are required")
	}
	switch kind {
	case "finding":
		return runExplain(ctx, findingArgs{
			ObservationsDir: args.Observations,
			ControlsDir:     args.Controls,
			FindingID:       args.ID,
		})
	case "asset":
		return contextAsset(ctx, args)
	case "chain":
		return contextChain(ctx, args)
	case "framework":
		return runCompliance(ctx, complianceArgs{ObservationsDir: args.Observations, Framework: args.ID})
	case "requirement":
		return contextRequirement(ctx, args)
	default:
		return nil, fmt.Errorf("unknown context type %q (want finding | asset | chain | requirement | framework)", args.Type)
	}
}

// contextApply runs the evaluation shared by the asset and chain
// drill-downs (chains need ChainsDir).
func contextApply(ctx context.Context, args contextArgs) (*stave.Assessment, error) {
	if args.Observations == "" {
		return nil, errors.New("observations is required for this context type")
	}
	return stave.Apply(ctx, stave.Config{
		SnapshotsDir:      args.Observations,
		ControlsDir:       args.Controls,
		ChainsDir:         resolveChainsDir(args.Chains),
		AllowUnknownInput: args.AllowUnknownInput,
	})
}

// contextAsset returns every finding on one asset, with the chains
// each finding participates in.
func contextAsset(ctx context.Context, args contextArgs) (any, error) {
	assess, err := contextApply(ctx, args)
	if err != nil {
		return nil, err
	}
	findings := assess.FindingsForAsset(stave.AssetID(args.ID))
	items := make([]map[string]any, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		chains := make([]string, 0, len(f.ChainMembership))
		for _, m := range f.ChainMembership {
			chains = append(chains, string(m.ChainID))
		}
		items = append(items, map[string]any{
			"control_id":   f.ControlID,
			"control_name": f.ControlName,
			"severity":     f.Severity,
			"message":      findingMessage(f),
			"chains":       chains,
		})
	}
	return map[string]any{
		"asset_id":      args.ID,
		"finding_count": len(items),
		"findings":      items,
	}, nil
}

// contextChain returns one chain's full detail: legs, narrative,
// attack stages, and participating assets.
func contextChain(ctx context.Context, args contextArgs) (any, error) {
	assess, err := contextApply(ctx, args)
	if err != nil {
		return nil, err
	}
	for i := range assess.ChainFindings {
		c := &assess.ChainFindings[i]
		if string(c.ChainID) != args.ID {
			continue
		}
		_, assets := chainAssets(assess, c.ChainID)
		assetList := make([]string, 0, len(assets))
		for a := range assets {
			assetList = append(assetList, a)
		}
		sort.Strings(assetList)
		controls := make([]string, len(c.ControlsFailing))
		for j, cf := range c.ControlsFailing {
			controls[j] = string(cf)
		}
		return map[string]any{
			"chain_id":             c.ChainID,
			"severity":             c.Severity,
			"compound_score":       c.CompoundScore,
			"description":          c.Description,
			"narrative":            c.Narrative,
			"attack_stages":        c.AttackStages,
			"controls_failing":     controls,
			"participating_assets": assetList,
		}, nil
	}
	return nil, fmt.Errorf("chain %q not found in this snapshot", args.ID)
}

// contextRequirement returns one compliance requirement's status and
// failing controls. Requires the framework alongside the requirement ID.
func contextRequirement(ctx context.Context, args contextArgs) (any, error) {
	if args.Framework == "" {
		return nil, errors.New("framework is required for requirement context")
	}
	report, err := stave.Compliance(ctx, args.Observations, args.Framework)
	if err != nil {
		return nil, err
	}
	for i := range report.Requirements {
		r := &report.Requirements[i]
		if r.RequirementID != args.ID {
			continue
		}
		status := "PASS"
		switch {
		case r.IsNotEvaluated():
			status = "N/A"
		case !r.IsMet():
			status = "FAIL"
		}
		fails := make([]map[string]any, 0)
		for _, e := range r.Evidence {
			if e.IsFail() {
				fails = append(fails, map[string]any{
					"control_id":   e.ControlID,
					"asset":        e.ResourceARN,
					"control_name": e.ControlName,
				})
			}
		}
		return map[string]any{
			"requirement_id":   r.RequirementID,
			"description":      r.Description,
			"section":          r.Section,
			"status":           status,
			"pass_count":       r.PassCount,
			"fail_count":       r.FailCount,
			"total_controls":   r.TotalControls,
			"framework":        args.Framework,
			"failing_controls": fails,
		}, nil
	}
	return nil, fmt.Errorf("requirement %q not found in framework %q", args.ID, args.Framework)
}
