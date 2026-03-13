package extractor

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/sufield/stave/internal/domain/kernel"
)

// templateData holds the variables used across all scaffolded files.
type templateData struct {
	Name          string
	SchemaVersion string
}

func newTemplateData(name string) templateData {
	return templateData{
		Name:          name,
		SchemaVersion: string(kernel.SchemaObservation),
	}
}

// --- File Generators ---

func extractorReadme(name string) string {
	return render("readme", readmeTmpl, newTemplateData(name))
}

func extractorMetadata(name string) string {
	return render("metadata", metadataTmpl, newTemplateData(name))
}

func extractorTransformGo(name string) string {
	return render("transform", transformTmpl, newTemplateData(name))
}

func extractorTransformTestGo(name string) string {
	return render("test", testTmpl, newTemplateData(name))
}

func extractorMakefile(name string) string {
	return render("makefile", makefileTmpl, newTemplateData(name))
}

// --- Helper ---

func render(name, tpl string, data templateData) string {
	// Create template and add a helper for backticks in generated code
	t := template.Must(template.New(name).Funcs(template.FuncMap{
		"tick": func() string { return "`" },
	}).Parse(tpl))

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		// This should only happen during development (syntax error in template)
		panic(fmt.Sprintf("failed to render template %s: %v", name, err))
	}

	return normalizeTemplate(buf.String())
}

// --- Templates ---

const readmeTmpl = `# {{ .Name }} Extractor

Custom Stave extractor for transforming raw input into observation snapshots.

## Usage

1. Edit {{ tick }}transform.go{{ tick }} to implement your extraction logic.
2. Run tests: {{ tick }}make test{{ tick }}
3. Build: {{ tick }}make build{{ tick }}

## Workflow

` + "```bash" + `
# Transform raw input into an observation snapshot
go run . --input raw-data.json --output observations/snapshot.json

# Validate the output
stave validate --in observations/snapshot.json
` + "```" + `

## Metadata

See {{ tick }}extractor.yaml{{ tick }} for extractor name, version, and source type.
`

const metadataTmpl = `
name: {{ .Name }}
version: "0.1.0"
source_type: {{ .Name }}
description: "Custom extractor for {{ .Name }} data sources"
`

const transformTmpl = `package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Observation represents a Stave observation snapshot.
type Observation struct {
	SchemaVersion string    {{ tick }}json:"schema_version"{{ tick }}
	CapturedAt    time.Time {{ tick }}json:"captured_at"{{ tick }}
	GeneratedBy   Generated {{ tick }}json:"generated_by"{{ tick }}
	Assets        []Asset   {{ tick }}json:"assets"{{ tick }}
}

// Generated describes the tool that produced this observation.
type Generated struct {
	Tool       string {{ tick }}json:"tool"{{ tick }}
	Version    string {{ tick }}json:"version"{{ tick }}
	SourceType string {{ tick }}json:"source_type"{{ tick }}
}

// Asset represents a single observed asset.
type Asset struct {
	ID         string         {{ tick }}json:"id"{{ tick }}
	Type       string         {{ tick }}json:"type"{{ tick }}
	Properties map[string]any {{ tick }}json:"properties"{{ tick }}
}

// Transform reads raw input and produces a Stave observation snapshot.
func Transform(inputPath string) (*Observation, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}

	// TODO: Parse your raw input format here.
	_ = data

	obs := &Observation{
		SchemaVersion: "{{ .SchemaVersion }}",
		CapturedAt:    time.Now().UTC(),
		GeneratedBy: Generated{
			Tool:       "{{ .Name }}",
			Version:    "0.1.0",
			SourceType: "{{ .Name }}",
		},
		Assets: []Asset{
			{
				ID:   "example-asset",
				Type: "example",
				Properties: map[string]any{
					"placeholder": true,
				},
			},
		},
	}
	return obs, nil
}

func main() {
	if len(os.Args) < 3 || os.Args[1] != "--input" {
		fmt.Fprintln(os.Stderr, "Usage: {{ .Name }} --input <file> [--output <file>]")
		os.Exit(2)
	}

	inputPath := os.Args[2]
	obs, err := Transform(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	out := os.Stdout
	if len(os.Args) >= 5 && os.Args[3] == "--output" {
		f, ferr := os.OpenFile(os.Args[4], os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", ferr)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(obs); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
`

const testTmpl = `package main

import (
	"os"
	"testing"
)

func TestTransform(t *testing.T) {
	// Create a temporary input file
	tmpFile, err := os.CreateTemp(t.TempDir(), "input-*.json")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := tmpFile.WriteString("{}"); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	tmpFile.Close()

	obs, err := Transform(tmpFile.Name())
	if err != nil {
		t.Fatalf("Transform() error: %v", err)
	}
	if obs.SchemaVersion != "{{ .SchemaVersion }}" {
		t.Errorf("SchemaVersion = %q, want {{ .SchemaVersion }}", obs.SchemaVersion)
	}
	if obs.GeneratedBy.SourceType != "{{ .Name }}" {
		t.Errorf("SourceType = %q, want {{ .Name }}", obs.GeneratedBy.SourceType)
	}
	if len(obs.Assets) == 0 {
		t.Error("expected at least one asset")
	}
}
`

const makefileTmpl = `.PHONY: build test clean

build:
	go build -o {{ .Name }} .

test:
	go test -v ./...

clean:
	rm -f {{ .Name }}
`
