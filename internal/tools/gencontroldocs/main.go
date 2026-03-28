// Command gencontroldocs generates a markdown control reference from the
// built-in control catalog. Single source of truth: the control YAML files
// embedded in the binary.
//
// Usage:
//
//	go run ./internal/tools/gencontroldocs                       # write docs/controls/reference.md
//	go run ./internal/tools/gencontroldocs -check                # exit 1 if reference.md is stale
//	go run ./internal/tools/gencontroldocs -out docs/controls/reference.md
package main

import (
	"bytes"
	"cmp"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/template"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/builtin/predicate"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/crypto"
)

func main() {
	outPath := flag.String("out", "docs/controls/reference.md", "output file")
	check := flag.Bool("check", false, "check mode: exit 1 if output is stale")
	flag.Parse()

	registry := ctlbuiltin.NewRegistry(
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

	var buf bytes.Buffer
	if err := referenceTmpl.Execute(&buf, data); err != nil {
		fmt.Fprintf(os.Stderr, "error: render template: %v\n", err)
		os.Exit(1)
	}

	if *check {
		existing, readErr := os.ReadFile(*outPath)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", readErr)
			os.Exit(1)
		}
		if !bytes.Equal(existing, buf.Bytes()) {
			fmt.Fprintf(os.Stderr, "%s is stale. Run: go run ./internal/tools/gencontroldocs\n", *outPath)
			os.Exit(1)
		}
		return
	}

	if err := os.WriteFile(*outPath, buf.Bytes(), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "error: write %s: %v\n", *outPath, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d controls)\n", *outPath, catalog.Len())
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

type templateData struct {
	Total    int
	PackHash string
	Controls []controlData
	ByDomain []countEntry
	BySev    []countEntry
}

func buildTemplateData(catalog *policy.Catalog, hasher ports.Digester) templateData {
	controls := catalog.List()
	byDomain := make(map[string]int)
	bySev := make(map[string]int)

	data := templateData{
		Total:    len(controls),
		PackHash: string(catalog.PackHash(hasher)),
	}

	for _, ctl := range controls {
		domain := ctl.Domain
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
			cd.Compliance = append(cd.Compliance, k+": "+v)
		}
		slices.Sort(cd.Compliance)

		if ctl.Remediation != nil && ctl.Remediation.Actionable() {
			cd.HasAction = true
			cd.Action = strings.TrimSpace(ctl.Remediation.Action)
		}

		data.Controls = append(data.Controls, cd)
	}

	data.BySev = sortedCounts(bySev)
	data.ByDomain = sortedCounts(byDomain)

	return data
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

var referenceTmpl = template.Must(template.New("reference").Parse(`# Control Reference

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: ` + "`go run ./internal/tools/gencontroldocs`" + `

**Total controls:** {{.Total}}
**Pack hash:** ` + "`{{.PackHash}}`" + `

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

## Controls

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
