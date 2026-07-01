package stave

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/sufield/stave/internal/util/jsonutil"
	"gopkg.in/yaml.v3"
)

// ServiceEntry is one service in the registry.
type ServiceEntry struct {
	ID        string `yaml:"id"         json:"id"`
	Name      string `yaml:"name"       json:"name"`
	ShortName string `yaml:"short_name" json:"short_name"`
	Category  string `yaml:"category"   json:"category"`
	Status    string `yaml:"status"     json:"status,omitempty"`
	Notes     string `yaml:"notes"      json:"notes,omitempty"`
}

type serviceRegistryFile struct {
	Services []ServiceEntry `yaml:"services"`
}

// ServiceWithControls is a service entry enriched with live control count.
type ServiceWithControls struct {
	ServiceEntry
	Controls int `json:"controls"`
}

// ServicesListOptions parameterizes [RenderServicesList].
type ServicesListOptions struct {
	RegistryPath string
	ControlsDir  string
	Format       string // "json" or "text"/""
	Status       string
	Category     string
	HasControls  bool
	NoControls   bool
}

// ServicesInspectOptions parameterizes [RenderServicesInspect].
type ServicesInspectOptions struct {
	ServiceID    string
	RegistryPath string
	ControlsDir  string
	Format       string
}

// ServicesCoverageOptions parameterizes [RenderServicesCoverage].
type ServicesCoverageOptions struct {
	RegistryPath string
	ControlsDir  string
	Format       string
	Category     string
}

func loadServicesRegistry(path string) ([]ServiceEntry, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("load service registry: %w", err)
	}
	var f serviceRegistryFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse service registry: %w", err)
	}
	seen := make(map[string]struct{}, len(f.Services))
	for i := range f.Services {
		svc := &f.Services[i]
		if svc.ID == "" {
			return nil, fmt.Errorf("service registry entry %d: missing id", i)
		}
		if _, dup := seen[svc.ID]; dup {
			return nil, fmt.Errorf("service registry: duplicate id %q", svc.ID)
		}
		seen[svc.ID] = struct{}{}
		if svc.Status == "" {
			svc.Status = "active"
		}
	}
	return f.Services, nil
}

func enrichWithControls(ctx context.Context, services []ServiceEntry, controlsDir string) ([]ServiceWithControls, error) {
	controls, err := loadControlsFromDir(ctx, controlsDir)
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int, len(services))
	for i := range controls {
		id := string(controls[i].ID)
		if !strings.HasPrefix(id, "CTL.") {
			continue
		}
		rest := strings.TrimPrefix(id, "CTL.")
		svc, _, ok := strings.Cut(rest, ".")
		if !ok {
			continue
		}
		counts[strings.ToLower(svc)]++
	}
	out := make([]ServiceWithControls, len(services))
	for i := range services {
		out[i] = ServiceWithControls{
			ServiceEntry: services[i],
			Controls:     counts[services[i].ID],
		}
	}
	return out, nil
}

// RenderServicesList is the library entry point behind `stave services list`.
func RenderServicesList(ctx context.Context, opts ServicesListOptions) ([]byte, error) {
	services, err := loadServicesRegistry(opts.RegistryPath)
	if err != nil {
		return nil, err
	}
	enriched, err := enrichWithControls(ctx, services, opts.ControlsDir)
	if err != nil {
		return nil, err
	}

	filtered := make([]ServiceWithControls, 0, len(enriched))
	for i := range enriched {
		s := &enriched[i]
		if opts.Status != "" && !strings.EqualFold(s.Status, opts.Status) {
			continue
		}
		if opts.Category != "" && !strings.EqualFold(s.Category, opts.Category) {
			continue
		}
		if opts.HasControls && s.Controls == 0 {
			continue
		}
		if opts.NoControls && s.Controls > 0 {
			continue
		}
		filtered = append(filtered, *s)
	}
	slices.SortFunc(filtered, func(a, b ServiceWithControls) int {
		return cmp.Compare(a.ID, b.ID)
	})

	var buf bytes.Buffer
	if opts.Format == "json" {
		if err := jsonutil.WriteIndented(&buf, filtered); err != nil {
			return nil, fmt.Errorf("render services list: %w", err)
		}
	} else {
		renderServicesListText(&buf, filtered)
	}
	return buf.Bytes(), nil
}

func renderServicesListText(buf *bytes.Buffer, services []ServiceWithControls) {
	tw := tabwriter.NewWriter(buf, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVICE\tSHORT\tCATEGORY\tSTATUS\tCONTROLS")
	for i := range services {
		s := &services[i]
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n",
			s.ID, s.ShortName, s.Category, s.Status, s.Controls)
	}
	_ = tw.Flush()

	active, known, oos, retired := 0, 0, 0, 0
	totalControls := 0
	for i := range services {
		totalControls += services[i].Controls
		switch services[i].Status {
		case "active":
			active++
		case "known_not_covered":
			known++
		case "out_of_scope":
			oos++
		case "retired":
			retired++
		}
	}
	fmt.Fprintf(buf, "\nActive: %d services, %d controls\n", active, totalControls)
	if known > 0 {
		fmt.Fprintf(buf, "Known not covered: %d services\n", known)
	}
	if oos > 0 {
		fmt.Fprintf(buf, "Out of scope: %d services\n", oos)
	}
	if retired > 0 {
		fmt.Fprintf(buf, "Retired: %d services\n", retired)
	}
}

type serviceControlRow struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Name     string `json:"name"`
}

type serviceInspectResult struct {
	ServiceWithControls
	ControlList []serviceControlRow `json:"control_list"`
}

// RenderServicesInspect is the library entry point behind `stave services inspect`.
func RenderServicesInspect(ctx context.Context, opts ServicesInspectOptions) ([]byte, error) {
	services, err := loadServicesRegistry(opts.RegistryPath)
	if err != nil {
		return nil, err
	}
	enriched, err := enrichWithControls(ctx, services, opts.ControlsDir)
	if err != nil {
		return nil, err
	}

	var found *ServiceWithControls
	for i := range enriched {
		if strings.EqualFold(enriched[i].ID, opts.ServiceID) {
			found = &enriched[i]
			break
		}
	}
	if found == nil {
		return nil, fmt.Errorf("service %q not found in registry: %w", opts.ServiceID, ErrInvalidInput)
	}

	controls, err := loadControlsFromDir(ctx, opts.ControlsDir)
	if err != nil {
		return nil, err
	}
	var rows []serviceControlRow
	for i := range controls {
		id := string(controls[i].ID)
		if !strings.HasPrefix(id, "CTL.") {
			continue
		}
		rest := strings.TrimPrefix(id, "CTL.")
		svc, _, ok := strings.Cut(rest, ".")
		if !ok {
			continue
		}
		if !strings.EqualFold(svc, opts.ServiceID) {
			continue
		}
		rows = append(rows, serviceControlRow{
			ID:       id,
			Severity: strings.ToUpper(controls[i].Severity.String()),
			Name:     controls[i].Name,
		})
	}
	slices.SortFunc(rows, func(a, b serviceControlRow) int {
		return cmp.Compare(a.ID, b.ID)
	})

	result := serviceInspectResult{
		ServiceWithControls: *found,
		ControlList:         rows,
	}

	var buf bytes.Buffer
	if opts.Format == "json" {
		if err := jsonutil.WriteIndented(&buf, result); err != nil {
			return nil, fmt.Errorf("render services inspect: %w", err)
		}
	} else {
		renderServicesInspectText(&buf, result)
	}
	return buf.Bytes(), nil
}

func renderServicesInspectText(buf *bytes.Buffer, r serviceInspectResult) {
	fmt.Fprintf(buf, "SERVICE: %s (%s)\n", r.Name, r.ShortName)
	fmt.Fprintf(buf, "  ID:       %s\n", r.ID)
	fmt.Fprintf(buf, "  Category: %s\n", r.Category)
	fmt.Fprintf(buf, "  Status:   %s\n", r.Status)
	if r.Notes != "" {
		fmt.Fprintf(buf, "  Notes:    %s\n", r.Notes)
	}
	fmt.Fprintf(buf, "\nCONTROLS (%d):\n", r.Controls)
	if len(r.ControlList) == 0 {
		fmt.Fprintln(buf, "  (none)")
		return
	}
	tw := tabwriter.NewWriter(buf, 0, 4, 2, ' ', 0)
	for i := range r.ControlList {
		c := &r.ControlList[i]
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", c.ID, c.Severity, c.Name)
	}
	_ = tw.Flush()
}

type categoryCoverage struct {
	Category string `json:"category"`
	Services int    `json:"services"`
	Active   int    `json:"active"`
	Controls int    `json:"controls"`
}

type servicesCoverageReport struct {
	Total      int                `json:"total"`
	Active     int                `json:"active"`
	KnownGaps  int                `json:"known_not_covered"`
	OutOfScope int                `json:"out_of_scope"`
	Retired    int                `json:"retired"`
	Preview    int                `json:"preview"`
	Controls   int                `json:"controls"`
	ByCategory []categoryCoverage `json:"by_category"`
}

// RenderServicesCoverage is the library entry point behind `stave services coverage`.
func RenderServicesCoverage(ctx context.Context, opts ServicesCoverageOptions) ([]byte, error) {
	services, err := loadServicesRegistry(opts.RegistryPath)
	if err != nil {
		return nil, err
	}
	enriched, err := enrichWithControls(ctx, services, opts.ControlsDir)
	if err != nil {
		return nil, err
	}

	catMap := map[string]*categoryCoverage{}
	var report servicesCoverageReport
	for i := range enriched {
		s := &enriched[i]
		if opts.Category != "" && !strings.EqualFold(s.Category, opts.Category) {
			continue
		}
		report.Total++
		report.Controls += s.Controls
		switch s.Status {
		case "active":
			report.Active++
		case "known_not_covered":
			report.KnownGaps++
		case "out_of_scope":
			report.OutOfScope++
		case "retired":
			report.Retired++
		case "preview":
			report.Preview++
		}

		cc := catMap[s.Category]
		if cc == nil {
			cc = &categoryCoverage{Category: s.Category}
			catMap[s.Category] = cc
		}
		cc.Services++
		cc.Controls += s.Controls
		if s.Controls > 0 {
			cc.Active++
		}
	}
	cats := make([]categoryCoverage, 0, len(catMap))
	for _, cc := range catMap {
		cats = append(cats, *cc)
	}
	slices.SortFunc(cats, func(a, b categoryCoverage) int {
		if a.Controls != b.Controls {
			return cmp.Compare(b.Controls, a.Controls)
		}
		return cmp.Compare(a.Category, b.Category)
	})
	report.ByCategory = cats

	var buf bytes.Buffer
	if opts.Format == "json" {
		if err := jsonutil.WriteIndented(&buf, report); err != nil {
			return nil, fmt.Errorf("render services coverage: %w", err)
		}
	} else {
		renderServicesCoverageText(&buf, report)
	}
	return buf.Bytes(), nil
}

func renderServicesCoverageText(buf *bytes.Buffer, r servicesCoverageReport) {
	fmt.Fprintf(buf, "AWS Service Coverage\n")
	fmt.Fprintf(buf, "====================\n\n")
	fmt.Fprintf(buf, "  Total services tracked:    %d\n", r.Total)
	fmt.Fprintf(buf, "  Active (controls exist):   %d\n", r.Active)
	if r.KnownGaps > 0 {
		fmt.Fprintf(buf, "  Known not covered:         %d\n", r.KnownGaps)
	}
	if r.OutOfScope > 0 {
		fmt.Fprintf(buf, "  Out of scope:              %d\n", r.OutOfScope)
	}
	if r.Retired > 0 {
		fmt.Fprintf(buf, "  Retired:                   %d\n", r.Retired)
	}
	if r.Preview > 0 {
		fmt.Fprintf(buf, "  Preview:                   %d\n", r.Preview)
	}
	fmt.Fprintf(buf, "  Total controls:            %d\n", r.Controls)

	fmt.Fprintf(buf, "\nCONTROL DENSITY BY CATEGORY:\n")
	tw := tabwriter.NewWriter(buf, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  CATEGORY\tCONTROLS\tSERVICES WITH CONTROLS")
	for i := range r.ByCategory {
		c := &r.ByCategory[i]
		gap := ""
		if c.Controls == 0 {
			gap = " <- gap"
		}
		fmt.Fprintf(tw, "  %s\t%d\t%d/%d%s\n",
			c.Category, c.Controls, c.Active, c.Services, gap)
	}
	_ = tw.Flush()
}
