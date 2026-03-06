package extractor

import "github.com/sufield/stave/internal/domain/kernel"

func extractorReadme(name string) string {
	return normalizeTemplate(`# ` + name + ` Extractor

Custom Stave extractor for transforming raw input into observation snapshots.

## Usage

1. Edit ` + "`transform.go`" + ` to implement your extraction logic.
2. Run tests: ` + "`make test`" + `
3. Build: ` + "`make build`" + `

## Workflow

` + "```bash" + `
# Transform raw input into an observation snapshot
go run . --input raw-data.json --output observations/snapshot.json

# Validate the output
stave validate --in observations/snapshot.json
` + "```" + `

## Metadata

See ` + "`extractor.yaml`" + ` for extractor name, version, and source type.
`)
}

func extractorMetadata(name string) string {
	return normalizeTemplate(`name: ` + name + `
version: "0.1.0"
source_type: ` + name + `
description: "Custom extractor for ` + name + ` data sources"
`)
}

func extractorTransformGo(name string) string {
	return normalizeTemplate(extractorTransformProgram(name))
}

func extractorTransformProgram(name string) string {
	return extractorTransformTypes() +
		extractorTransformFunction(name) +
		extractorTransformMain(name)
}

func extractorTransformTypes() string {
	return `package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Observation represents a Stave observation snapshot (obs.v0.1).
type Observation struct {
	SchemaVersion string    ` + "`json:\"schema_version\"`" + `
	CapturedAt    time.Time ` + "`json:\"captured_at\"`" + `
	GeneratedBy   Generated ` + "`json:\"generated_by\"`" + `
	Assets     []Asset ` + "`json:\"assets\"`" + `
}

// Generated describes the tool that produced this observation.
type Generated struct {
	Tool       string ` + "`json:\"tool\"`" + `
	Version    string ` + "`json:\"version\"`" + `
	SourceType string ` + "`json:\"source_type\"`" + `
}

// Asset represents a single observed asset.
type Asset struct {
	ID         string         ` + "`json:\"id\"`" + `
	Type       string         ` + "`json:\"type\"`" + `
	Properties map[string]any ` + "`json:\"properties\"`" + `
}
`
}

func extractorTransformFunction(name string) string {
	return `
// Transform reads raw input and produces a Stave observation snapshot.
func Transform(inputPath string) (*Observation, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}

	// TODO: Parse your raw input format here.
	_ = data

	obs := &Observation{
		SchemaVersion: "` + string(kernel.SchemaObservation) + `",
		CapturedAt:    time.Now().UTC(),
		GeneratedBy: Generated{
			Tool:       "` + name + `",
			Version:    "0.1.0",
			SourceType: "` + name + `",
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
`
}

func extractorTransformMain(name string) string {
	return `func main() {
	if len(os.Args) < 3 || os.Args[1] != "--input" {
		fmt.Fprintln(os.Stderr, "Usage: ` + name + ` --input <file> [--output <file>]")
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
}

func extractorTransformTestGo(name string) string {
	return normalizeTemplate(`package main

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
	if _, err := tmpFile.WriteString(` + "`{}`" + `); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	tmpFile.Close()

	obs, err := Transform(tmpFile.Name())
	if err != nil {
		t.Fatalf("Transform() error: %v", err)
	}
	if obs.SchemaVersion != "` + string(kernel.SchemaObservation) + `" {
		t.Errorf("SchemaVersion = %q, want ` + string(kernel.SchemaObservation) + `", obs.SchemaVersion)
	}
	if obs.GeneratedBy.SourceType != "` + name + `" {
		t.Errorf("SourceType = %q, want ` + name + `", obs.GeneratedBy.SourceType)
	}
	if len(obs.Assets) == 0 {
		t.Error("expected at least one asset")
	}
}
`)
}

func extractorMakefile(name string) string {
	return normalizeTemplate(`.PHONY: build test clean

build:
	go build -o ` + name + ` .

test:
	go test -v ./...

clean:
	rm -f ` + name + `
`)
}
