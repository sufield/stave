package stave

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/sufield/stave/internal/util/jsonutil"
)

// CatalogCoverageOptions parameterizes [RenderCatalogCoverage].
type CatalogCoverageOptions struct {
	ControlsDir string
	Format      string // "json" or "text"/""
}

type catalogCoverageReport struct {
	TotalControls int                      `json:"total_controls"`
	TotalServices int                      `json:"total_services"`
	Services      []catalogCoverageService `json:"services"`
}

type catalogCoverageService struct {
	Service    string   `json:"service"`
	Controls   int      `json:"controls"`
	Categories int      `json:"categories"`
	AssetTypes []string `json:"asset_types"`
}

// RenderCatalogCoverage computes per-service control coverage from
// the catalog: how many controls and categories each service has, and
// the asset types they apply to.
func RenderCatalogCoverage(ctx context.Context, opts CatalogCoverageOptions) ([]byte, error) {
	controls, err := loadControlsFromDir(ctx, opts.ControlsDir)
	if err != nil {
		return nil, err
	}

	type svcData struct {
		controls   int
		categories map[string]struct{}
		assetTypes map[string]struct{}
	}
	byService := map[string]*svcData{}
	for i := range controls {
		svc, cat := catalogParseControlID(string(controls[i].ID))
		if svc == "" {
			continue
		}
		d := byService[svc]
		if d == nil {
			d = &svcData{categories: map[string]struct{}{}, assetTypes: map[string]struct{}{}}
			byService[svc] = d
		}
		d.controls++
		if cat != "" {
			d.categories[cat] = struct{}{}
		}
		for _, at := range controls[i].ApplicableAssetTypes {
			d.assetTypes[string(at)] = struct{}{}
		}
	}

	services := make([]catalogCoverageService, 0, len(byService))
	for svc, d := range byService {
		ats := make([]string, 0, len(d.assetTypes))
		for at := range d.assetTypes {
			ats = append(ats, at)
		}
		slices.Sort(ats)
		services = append(services, catalogCoverageService{
			Service:    svc,
			Controls:   d.controls,
			Categories: len(d.categories),
			AssetTypes: ats,
		})
	}
	slices.SortFunc(services, func(a, b catalogCoverageService) int {
		return cmp.Compare(a.Service, b.Service)
	})

	report := catalogCoverageReport{
		TotalControls: len(controls),
		TotalServices: len(byService),
		Services:      services,
	}

	var buf bytes.Buffer
	if opts.Format == "json" {
		if err := jsonutil.WriteIndented(&buf, report); err != nil {
			return nil, fmt.Errorf("render catalog coverage: %w", err)
		}
	} else {
		renderCatalogCoverageText(&buf, report)
	}
	return buf.Bytes(), nil
}

func renderCatalogCoverageText(buf *bytes.Buffer, r catalogCoverageReport) {
	fmt.Fprintf(buf, "Catalog Coverage: %d controls across %d services\n\n", r.TotalControls, r.TotalServices)

	tw := tabwriter.NewWriter(buf, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVICE\tCONTROLS\tCATEGORIES\tASSET TYPES")
	for i := range r.Services {
		svc := &r.Services[i]
		atSummary := strings.Join(svc.AssetTypes, ", ")
		if len(atSummary) > 60 {
			atSummary = atSummary[:57] + "..."
		}
		if atSummary == "" {
			atSummary = "-"
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\n",
			strings.ToUpper(svc.Service), svc.Controls, svc.Categories, atSummary)
	}
	_ = tw.Flush()
}

// catalogParseControlID duplicates the service/category extraction
// from the capabilities package. Kept here to avoid importing
// internal/app/capabilities from the facade for a trivial parse.
func catalogParseControlID(id string) (string, string) {
	if !strings.HasPrefix(id, "CTL.") {
		return "", ""
	}
	rest := strings.TrimPrefix(id, "CTL.")
	svc, rest2, ok := strings.Cut(rest, ".")
	if !ok {
		return "", ""
	}
	cat, _, _ := strings.Cut(rest2, ".")
	return strings.ToLower(svc), strings.ToLower(cat)
}
