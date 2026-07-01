package stave

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// CatalogInspectOptions parameterizes [RenderCatalogInspect].
type CatalogInspectOptions struct {
	ControlID   string
	ControlsDir string
	ChainsDir   string
	Format      string // "json" or "text"/""
}

// ControlDetail is the public metadata shape for a single control,
// returned by the inspect subcommand. Exported for JSON serialization.
type ControlDetail struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	Description          string            `json:"description"`
	Severity             string            `json:"severity"`
	Domain               string            `json:"domain"`
	Scope                string            `json:"scope,omitempty"`
	Type                 string            `json:"type"`
	Classification       string            `json:"classification"`
	CorpusReference      string            `json:"corpus_reference,omitempty"`
	ApplicableAssetTypes []string          `json:"applicable_asset_types,omitempty"`
	Compliance           map[string]string `json:"compliance,omitempty"`
	ObservationFields    []string          `json:"observation_fields,omitempty"`
	Chains               []string          `json:"chains,omitempty"`
	Remediation          *remediationView  `json:"remediation,omitempty"`
}

type remediationView struct {
	Description string `json:"description"`
	Action      string `json:"action"`
}

// RenderCatalogInspect loads the catalog, finds the control matching
// opts.ControlID, and renders its full metadata. Returns
// [ErrInvalidInput] when the ID is not found.
func RenderCatalogInspect(ctx context.Context, opts CatalogInspectOptions) ([]byte, error) {
	if opts.ControlID == "" {
		return nil, fmt.Errorf("control ID is required: %w", ErrInvalidInput)
	}

	controls, err := loadControlsFromDir(ctx, opts.ControlsDir)
	if err != nil {
		return nil, err
	}

	var found *policy.ControlDefinition
	for i := range controls {
		if strings.EqualFold(string(controls[i].ID), opts.ControlID) {
			found = &controls[i]
			break
		}
	}
	if found == nil {
		return nil, fmt.Errorf("control %q not found in catalog: %w", opts.ControlID, ErrInvalidInput)
	}

	chains, err := loadChainsOptional(opts.ChainsDir)
	if err != nil {
		return nil, err
	}
	memberChains := chainsReferencing(chains, found.ID)

	detail := controlDetailFrom(found, memberChains)

	var buf bytes.Buffer
	if opts.Format == "json" {
		if err := jsonutil.WriteIndented(&buf, detail); err != nil {
			return nil, fmt.Errorf("render control detail: %w", err)
		}
	} else {
		renderControlDetailText(&buf, detail)
	}
	return buf.Bytes(), nil
}

func controlDetailFrom(c *policy.ControlDefinition, chainIDs []string) ControlDetail {
	assets := make([]string, 0, len(c.ApplicableAssetTypes))
	for _, at := range c.ApplicableAssetTypes {
		assets = append(assets, string(at))
	}

	var compliance map[string]string
	if len(c.Compliance) > 0 {
		compliance = make(map[string]string, len(c.Compliance))
		for k, v := range c.Compliance {
			compliance[string(k)] = string(v)
		}
	}

	var rem *remediationView
	if c.Remediation != nil {
		rem = &remediationView{
			Description: strings.TrimSpace(c.Remediation.Description),
			Action:      strings.TrimSpace(c.Remediation.Action),
		}
	}

	return ControlDetail{
		ID:                   string(c.ID),
		Name:                 c.Name,
		Description:          strings.Join(strings.Fields(c.Description), " "),
		Severity:             strings.ToUpper(c.Severity.String()),
		Domain:               string(c.Domain),
		Scope:                c.Scope,
		Type:                 c.Type.String(),
		Classification:       string(c.Classification),
		CorpusReference:      c.CorpusReference,
		ApplicableAssetTypes: assets,
		Compliance:           compliance,
		ObservationFields:    c.ObservationFields,
		Chains:               chainIDs,
		Remediation:          rem,
	}
}

func chainsReferencing(chains []policy.ChainDefinition, id kernel.ControlID) []string {
	var out []string
	for i := range chains {
		if slices.Contains(chains[i].ControlIDs, id) {
			out = append(out, string(chains[i].ID))
		}
	}
	slices.Sort(out)
	return out
}

func renderControlDetailText(buf *bytes.Buffer, d ControlDetail) {
	fmt.Fprintf(buf, "%s\n", d.ID)
	fmt.Fprintf(buf, "%s\n\n", strings.Repeat("=", len(d.ID)))

	fmt.Fprintf(buf, "  Name:            %s\n", d.Name)
	fmt.Fprintf(buf, "  Severity:        %s\n", d.Severity)
	fmt.Fprintf(buf, "  Domain:          %s\n", d.Domain)
	if d.Scope != "" {
		fmt.Fprintf(buf, "  Scope:           %s\n", d.Scope)
	}
	fmt.Fprintf(buf, "  Type:            %s\n", d.Type)
	fmt.Fprintf(buf, "  Classification:  %s\n", d.Classification)
	if d.CorpusReference != "" {
		fmt.Fprintf(buf, "  Corpus:          %s\n", d.CorpusReference)
	}

	if len(d.ApplicableAssetTypes) > 0 {
		fmt.Fprintf(buf, "\nApplicable Asset Types:\n")
		for _, at := range d.ApplicableAssetTypes {
			fmt.Fprintf(buf, "  %s\n", at)
		}
	}

	if len(d.Compliance) > 0 {
		fmt.Fprintf(buf, "\nCompliance:\n")
		keys := make([]string, 0, len(d.Compliance))
		for k := range d.Compliance {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			fmt.Fprintf(buf, "  %-20s %s\n", k+":", d.Compliance[k])
		}
	}

	if len(d.ObservationFields) > 0 {
		fmt.Fprintf(buf, "\nObservation Fields:\n")
		for _, f := range d.ObservationFields {
			fmt.Fprintf(buf, "  %s\n", f)
		}
	}

	if len(d.Chains) > 0 {
		fmt.Fprintf(buf, "\nChains:\n")
		for _, ch := range d.Chains {
			fmt.Fprintf(buf, "  %s\n", ch)
		}
	}

	if d.Remediation != nil {
		fmt.Fprintf(buf, "\nRemediation:\n")
		fmt.Fprintf(buf, "  %s\n", d.Remediation.Description)
		if d.Remediation.Action != "" {
			fmt.Fprintf(buf, "\n  Action: %s\n", d.Remediation.Action)
		}
	}

	fmt.Fprintf(buf, "\nDescription:\n  %s\n", d.Description)
}
