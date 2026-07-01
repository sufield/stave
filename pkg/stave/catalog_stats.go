package stave

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	appcaps "github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// CatalogStatsOptions parameterizes [RenderCatalogStats].
type CatalogStatsOptions struct {
	ControlsDir string
	ChainsDir   string
	Format      string // "json" or "text"/""
}

type catalogStatsReport struct {
	Controls    int                   `json:"controls"`
	Services    int                   `json:"services"`
	Chains      int                   `json:"chains"`
	Operational int                   `json:"operational"`
	Severity    map[string]int        `json:"severity"`
	ByService   []catalogServiceStats `json:"by_service"`
}

type catalogServiceStats struct {
	Service  string         `json:"service"`
	Controls int            `json:"controls"`
	Groups   int            `json:"groups"`
	MaxSev   string         `json:"max_severity"`
	Severity map[string]int `json:"severity"`
}

// RenderCatalogStats computes and renders aggregate catalog statistics.
// It is the library entry point behind `stave catalog stats`.
func RenderCatalogStats(ctx context.Context, opts CatalogStatsOptions) ([]byte, error) {
	controls, err := loadControlsFromDir(ctx, opts.ControlsDir)
	if err != nil {
		return nil, err
	}
	chains, err := loadChainsOptional(opts.ChainsDir)
	if err != nil {
		return nil, err
	}

	summary := appcaps.CatalogSummary(controls, chains)
	services := appcaps.ServiceRollup(controls)

	sevMap := make(map[string]int, len(summary.SeverityHist))
	for s, n := range summary.SeverityHist {
		sevMap[strings.ToUpper(s.String())] = n
	}

	byService := make([]catalogServiceStats, 0, len(services))
	for i := range services {
		row := &services[i]
		sev := make(map[string]int, len(row.Sev))
		for s, n := range row.Sev {
			sev[strings.ToUpper(s.String())] = n
		}
		byService = append(byService, catalogServiceStats{
			Service:  row.Service,
			Controls: row.Controls,
			Groups:   row.Caps,
			MaxSev:   strings.ToUpper(row.MaxSev.String()),
			Severity: sev,
		})
	}
	slices.SortFunc(byService, func(a, b catalogServiceStats) int {
		return cmp.Compare(a.Service, b.Service)
	})

	report := catalogStatsReport{
		Controls:    summary.Controls,
		Services:    summary.Services,
		Chains:      summary.Chains,
		Operational: summary.Operational,
		Severity:    sevMap,
		ByService:   byService,
	}

	var buf bytes.Buffer
	if opts.Format == "json" {
		if err := jsonutil.WriteIndented(&buf, report); err != nil {
			return nil, fmt.Errorf("render catalog stats: %w", err)
		}
	} else {
		renderCatalogStatsText(&buf, report, summary)
	}
	return buf.Bytes(), nil
}

func renderCatalogStatsText(buf *bytes.Buffer, r catalogStatsReport, s appcaps.Summary) {
	fmt.Fprintf(buf, "Catalog Statistics\n")
	fmt.Fprintf(buf, "==================\n\n")
	fmt.Fprintf(buf, "  Controls:     %d\n", r.Controls)
	fmt.Fprintf(buf, "  Services:     %d\n", r.Services)
	fmt.Fprintf(buf, "  Chains:       %d\n", r.Chains)
	fmt.Fprintf(buf, "  Operational:  %d\n\n", r.Operational)

	fmt.Fprintf(buf, "Severity: %s\n\n", catalogSeverityHistogram(s))

	tw := tabwriter.NewWriter(buf, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVICE\tCONTROLS\tGROUPS\tMAX SEVERITY")
	for i := range r.ByService {
		svc := &r.ByService[i]
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\n",
			strings.ToUpper(svc.Service), svc.Controls, svc.Groups, svc.MaxSev)
	}
	_ = tw.Flush()
}
