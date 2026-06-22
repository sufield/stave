// Command gencontroldocs generates a markdown control reference from the
// built-in control catalog. Single source of truth: the control YAML files
// embedded in the binary.
//
// Output is split so every file renders on GitHub (which refuses markdown
// over ~1 MB): a small index at docs/controls/reference.md plus one
// per-service file under docs/controls/reference/<service>.md. The index
// links to each per-service file.
//
// Usage:
//
//	go run ./internal/tools/gencontroldocs                       # write the index + per-service files
//	go run ./internal/tools/gencontroldocs -check                # exit 1 if any generated file is stale or orphaned
//	go run ./internal/tools/gencontroldocs -out docs/controls/reference.md
package main

import (
	"bytes"
	"cmp"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/predicate"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/crypto"
)

func main() {
	outPath := flag.String("out", "docs/controls/reference.md", "index output file")
	check := flag.Bool("check", false, "check mode: exit 1 if output is stale")
	flag.Parse()

	registry := ctlbuiltin.NewControlStore(
		ctlbuiltin.EmbeddedFS(), "embedded",
		ctlbuiltin.WithAliasResolver(predicate.ResolverFunc()),
	)
	controls, err := registry.All()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load controls: %v\n", err)
		os.Exit(1)
	}

	catalog := policy.NewCatalog(controls)
	hasher := crypto.NewHasher()

	data := buildTemplateData(catalog, hasher)

	// Render the index plus one file per service. Keyed by output path so
	// write and check share exactly the same target set.
	indexDir := filepath.Dir(*outPath)
	serviceDir := filepath.Join(indexDir, "reference")

	files := map[string][]byte{}

	var indexBuf bytes.Buffer
	if err := indexTmpl.Execute(&indexBuf, data); err != nil {
		fmt.Fprintf(os.Stderr, "error: render index: %v\n", err)
		os.Exit(1)
	}
	files[*outPath] = indexBuf.Bytes()

	for i := range data.Services {
		svc := &data.Services[i]
		var svcBuf bytes.Buffer
		if err := serviceTmpl.Execute(&svcBuf, svc); err != nil {
			fmt.Fprintf(os.Stderr, "error: render service %s: %v\n", svc.Name, err)
			os.Exit(1)
		}
		files[filepath.Join(serviceDir, svc.Slug+".md")] = svcBuf.Bytes()
	}

	if *check {
		os.Exit(runCheck(serviceDir, files))
	}

	if err := os.MkdirAll(serviceDir, 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "error: mkdir %s: %v\n", serviceDir, err)
		os.Exit(1)
	}
	for path, content := range files {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "error: write %s: %v\n", path, err)
			os.Exit(1)
		}
	}
	fmt.Printf("wrote %s + %d per-service files (%d controls)\n",
		*outPath, len(data.Services), catalog.Len())
}

// runCheck verifies every generated file matches disk and that no orphan
// per-service file lingers from a service that no longer exists. Returns a
// process exit code.
func runCheck(serviceDir string, files map[string][]byte) int {
	stale := false
	for path, want := range files {
		got, readErr := os.ReadFile(path) //nolint:gosec // generated paths under docs/
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "%s is missing: %v\n", path, readErr)
			stale = true
			continue
		}
		if !bytes.Equal(got, want) {
			fmt.Fprintf(os.Stderr, "%s is stale\n", path)
			stale = true
		}
	}
	// Orphan detection: any reference/*.md not in the generated set.
	entries, _ := filepath.Glob(filepath.Join(serviceDir, "*.md"))
	for _, e := range entries {
		if _, ok := files[e]; !ok {
			fmt.Fprintf(os.Stderr, "%s is orphaned (no matching service)\n", e)
			stale = true
		}
	}
	if stale {
		fmt.Fprintf(os.Stderr, "control reference is stale. Run: go run ./internal/tools/gencontroldocs\n")
		return 1
	}
	return 0
}

type controlData struct {
	ID          string
	Name        string
	Description string
	Severity    string
	Type        string
	Domain      string
	Compliance  []string
	HasAction   bool
	Action      string
}

type countEntry struct {
	Label string
	Count int
}

// serviceGroup is the per-service slice of the catalog rendered into its own
// file. Slug is the lowercase service name used for the filename and the
// index link.
type serviceGroup struct {
	Name     string
	Slug     string
	Controls []controlData
}

type templateData struct {
	Total    int
	PackHash string
	ByDomain []countEntry
	BySev    []countEntry
	Services []serviceGroup
}

func buildTemplateData(catalog *policy.Catalog, hasher ports.Digester) templateData {
	controls := catalog.List()
	byDomain := make(map[string]int)
	bySev := make(map[string]int)
	byService := make(map[string][]controlData)

	data := templateData{
		Total:    len(controls),
		PackHash: string(catalog.PackHash(hasher)),
	}

	for i := range controls {
		ctl := &controls[i]
		domain := string(ctl.Domain)
		if domain == "" {
			domain = "uncategorized"
		}
		byDomain[domain]++
		bySev[ctl.Severity.String()]++

		cd := controlData{
			ID:          ctl.ID.String(),
			Name:        ctl.Name,
			Description: strings.TrimSpace(ctl.Description),
			Severity:    ctl.Severity.String(),
			Type:        ctl.Type.String(),
			Domain:      domain,
		}

		for k, v := range ctl.Compliance {
			cd.Compliance = append(cd.Compliance, string(k)+": "+string(v))
		}
		slices.Sort(cd.Compliance)

		if ctl.Remediation != nil && ctl.Remediation.HasAction() {
			cd.HasAction = true
			cd.Action = strings.TrimSpace(ctl.Remediation.Action)
		}

		svc := serviceOf(cd.ID)
		byService[svc] = append(byService[svc], cd)
	}

	data.BySev = sortedCounts(bySev)
	data.ByDomain = sortedCounts(byDomain)
	data.Services = sortedServices(byService)

	return data
}

// serviceOf extracts the service segment from a control ID
// (CTL.IAM.PRIVESC.001 -> "IAM"). Falls back to "misc" for IDs that do not
// follow the CTL.<service>.* shape.
func serviceOf(id string) string {
	parts := strings.Split(id, ".")
	if len(parts) >= 2 && parts[1] != "" {
		return parts[1]
	}
	return "misc"
}

func sortedServices(m map[string][]controlData) []serviceGroup {
	groups := make([]serviceGroup, 0, len(m))
	for name, ctls := range m {
		slices.SortFunc(ctls, func(a, b controlData) int { return cmp.Compare(a.ID, b.ID) })
		groups = append(groups, serviceGroup{
			Name:     name,
			Slug:     strings.ToLower(name),
			Controls: ctls,
		})
	}
	slices.SortFunc(groups, func(a, b serviceGroup) int { return cmp.Compare(a.Name, b.Name) })
	return groups
}

func sortedCounts(m map[string]int) []countEntry {
	entries := make([]countEntry, 0, len(m))
	for k, v := range m {
		entries = append(entries, countEntry{Label: k, Count: v})
	}
	slices.SortFunc(entries, func(a, b countEntry) int {
		return cmp.Compare(a.Label, b.Label)
	})
	return entries
}

var indexTmpl = template.Must(template.New("index").Parse(`# Control Reference

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: ` + "`go run ./internal/tools/gencontroldocs`" + `

**Total controls:** {{.Total}}
**Pack hash:** ` + "`{{.PackHash}}`" + `

The full per-control detail is split by service so every page renders on
GitHub. Pick a service below.

## Summary

| Severity | Count |
|----------|-------|
{{- range .BySev}}
| {{.Label}} | {{.Count}} |
{{- end}}

| Domain | Count |
|--------|-------|
{{- range .ByDomain}}
| {{.Label}} | {{.Count}} |
{{- end}}

## Controls by service

| Service | Controls |
|---------|----------|
{{- range .Services}}
| [{{.Name}}](reference/{{.Slug}}.md) | {{len .Controls}} |
{{- end}}
`))

var serviceTmpl = template.Must(template.New("service").Parse(`# Control Reference — {{.Name}}

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: ` + "`go run ./internal/tools/gencontroldocs`" + `
>
> Back to the [control reference index](../reference.md).

{{range .Controls -}}
### {{.ID}}

**{{.Name}}**

- **Severity:** {{.Severity}}
- **Type:** {{.Type}}
- **Domain:** {{.Domain}}
{{- if .Compliance}}
- **Compliance:**{{range .Compliance}} {{.}};{{end}}
{{- end}}

{{.Description}}
{{if .HasAction}}
**Remediation:** {{.Action}}
{{end}}
---

{{end -}}
`))
