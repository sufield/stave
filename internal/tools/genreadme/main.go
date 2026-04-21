// Command genreadme renders README.md from README.md.tmpl using live data
// from the repository (VERSION file, control file counts).
//
// Usage:
//
//	go run ./internal/tools/genreadme                    # write README.md
//	go run ./internal/tools/genreadme -check             # exit 1 if README.md is stale
//	go run ./internal/tools/genreadme -tmpl internal/tools/genreadme/README.md.tmpl -out README.md
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

type Data struct {
	Version       string
	TotalControls int
	CategoryCount int
	S3            map[string]int // S3 category → control count
	DomainTotals  map[string]int // domain → total control count
}

func main() {
	tmplPath := flag.String("tmpl", "internal/tools/genreadme/README.md.tmpl", "template file")
	outPath := flag.String("out", "README.md", "output file")
	controlsRoot := flag.String("controls", "controls", "controls root directory")
	check := flag.Bool("check", false, "check mode: exit 1 if output is stale")
	flag.Parse()

	safeOut, err := safeLocalPath(*outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	data, err := collect(*controlsRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	rendered, err := render(*tmplPath, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *check {
		existing, err := os.ReadFile(safeOut) //nolint:gosec // path validated by safeLocalPath
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", safeOut, err)
			os.Exit(1)
		}
		if !bytes.Equal(existing, rendered) {
			fmt.Fprintf(os.Stderr, "FAIL: %s is stale. Run 'make readme' to update.\n", safeOut)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "OK: %s is up to date\n", safeOut)
		return
	}

	if err := os.WriteFile(safeOut, rendered, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", safeOut, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Wrote %s (%d controls across %d domains)\n",
		safeOut, data.TotalControls, len(data.DomainTotals))
}

func collect(controlsRoot string) (Data, error) {
	version, err := os.ReadFile("VERSION")
	if err != nil {
		return Data{}, fmt.Errorf("reading VERSION: %w", err)
	}

	s3 := make(map[string]int)
	domainTotals := make(map[string]int)
	total := 0
	categoryCount := 0

	domains, err := os.ReadDir(controlsRoot)
	if err != nil {
		return Data{}, fmt.Errorf("reading controls root: %w", err)
	}

	for _, domain := range domains {
		if !domain.IsDir() {
			continue
		}
		domainName := domain.Name()
		if strings.HasPrefix(domainName, "_") || strings.HasPrefix(domainName, ".") {
			continue
		}
		domainDir := filepath.Join(controlsRoot, domainName)

		categories, err := os.ReadDir(domainDir)
		if err != nil {
			return Data{}, fmt.Errorf("reading domain %s: %w", domainName, err)
		}

		domainTotal := 0
		for _, cat := range categories {
			if !cat.IsDir() {
				continue
			}
			files, err := filepath.Glob(filepath.Join(domainDir, cat.Name(), "*.yaml"))
			if err != nil {
				return Data{}, fmt.Errorf("globbing %s/%s: %w", domainName, cat.Name(), err)
			}
			count := len(files)
			domainTotal += count
			categoryCount++

			if domainName == "s3" {
				s3[cat.Name()] = count
			}
		}

		domainTotals[domainName] = domainTotal
		total += domainTotal
	}

	return Data{
		Version:       strings.TrimSpace(string(version)),
		TotalControls: total,
		CategoryCount: categoryCount,
		S3:            s3,
		DomainTotals:  domainTotals,
	}, nil
}

// safeLocalPath rejects absolute paths and path traversal.
func safeLocalPath(p string) (string, error) {
	clean := filepath.Clean(p)
	if filepath.IsAbs(clean) {
		return "", fmt.Errorf("absolute paths not allowed: %s", p)
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal not allowed: %s", p)
	}
	return clean, nil
}

func render(tmplPath string, data Data) ([]byte, error) {
	safe, err := safeLocalPath(tmplPath)
	if err != nil {
		return nil, err
	}

	funcMap := template.FuncMap{
		"ctrl": func(category string) int {
			return data.S3[category]
		},
		"domain": func(name string) int {
			return data.DomainTotals[name]
		},
		"subtract": func(a, b int) int {
			return a - b
		},
	}

	tmplContent, err := os.ReadFile(safe) //nolint:gosec // path validated by safeLocalPath
	if err != nil {
		return nil, fmt.Errorf("reading template: %w", err)
	}

	t, err := template.New("readme").Funcs(funcMap).Parse(string(tmplContent))
	if err != nil {
		return nil, fmt.Errorf("parsing template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("executing template: %w", err)
	}

	return buf.Bytes(), nil
}
