// Package awsmeta reads AWS service model metadata from botocore's
// bundled service-2.json files. It extracts API operations and their
// response field schemas. No AWS credentials required.
package awsmeta

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ServiceSchema holds extracted API metadata for one service.
type ServiceSchema struct {
	ServiceName string      `json:"service_name"`
	Available   bool        `json:"available"`
	Operations  []Operation `json:"operations"`
}

// Operation holds one API operation's metadata.
type Operation struct {
	Name   string  `json:"name"`
	Type   string  `json:"type"` // "Describe" | "Get" | "List"
	Fields []Field `json:"fields"`
}

// Field holds one response field's metadata.
type Field struct {
	Path string `json:"path"`
	Kind string `json:"kind"` // "string" | "integer" | "boolean" | "list" | "structure" | "map" | "timestamp" | "blob" | "enum"
}

type serviceModel struct {
	Operations map[string]operationModel `json:"operations"`
	Shapes     map[string]shapeModel     `json:"shapes"`
}

type operationModel struct {
	Output *shapeRef `json:"output"`
}

type shapeRef struct {
	Shape string `json:"shape"`
}

type shapeModel struct {
	Type    string               `json:"type"`
	Members map[string]*shapeRef `json:"members"`
	Member  *shapeRef            `json:"member"` // list element type
	Enum    []string             `json:"enum"`
}

// SetDataDir sets the botocore data directory used by ExtractSchema.
// Callers must set this before calling ExtractSchema.
func SetDataDir(dir string) { botocoreDataDir = dir }

// ExtractSchema reads the botocore service model for the given service
// and returns Describe/Get/List operations with their response fields.
func ExtractSchema(serviceName string) (*ServiceSchema, error) {
	modelPath, err := findModelPath(serviceName)
	if err != nil {
		return &ServiceSchema{ServiceName: serviceName, Available: false}, nil //nolint:nilerr // not-found is Available=false, not an error
	}

	data, err := os.ReadFile(modelPath) //nolint:gosec // path is derived from botocore install, not user input
	if err != nil {
		return &ServiceSchema{ServiceName: serviceName, Available: false}, nil //nolint:nilerr // unreadable model is Available=false
	}

	var model serviceModel
	if err := json.Unmarshal(data, &model); err != nil {
		return nil, fmt.Errorf("parse service model: %w", err)
	}

	schema := &ServiceSchema{
		ServiceName: serviceName,
		Available:   true,
	}

	opNames := slices.Sorted(maps.Keys(model.Operations))

	for _, name := range opNames {
		op := model.Operations[name]
		opType := classifyOp(name)
		if opType == "" {
			continue
		}
		if op.Output == nil {
			continue
		}

		fields := flattenShape(&model, op.Output.Shape, "", 0)
		slices.SortFunc(fields, func(a, b Field) int {
			return strings.Compare(a.Path, b.Path)
		})

		schema.Operations = append(schema.Operations, Operation{
			Name:   name,
			Type:   opType,
			Fields: fields,
		})
	}

	return schema, nil
}

func classifyOp(name string) string {
	switch {
	case strings.HasPrefix(name, "Describe"):
		return "Describe"
	case strings.HasPrefix(name, "Get"):
		return "Get"
	case strings.HasPrefix(name, "List"):
		return "List"
	default:
		return ""
	}
}

func flattenShape(model *serviceModel, shapeName, prefix string, depth int) []Field {
	if depth > 8 {
		return nil
	}

	shape, ok := model.Shapes[shapeName]
	if !ok {
		return nil
	}

	if shape.Type != "structure" {
		return nil
	}

	memberNames := slices.Sorted(maps.Keys(shape.Members))

	var fields []Field
	for _, name := range memberNames {
		ref := shape.Members[name]
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}

		memberShape, ok := model.Shapes[ref.Shape]
		if !ok {
			fields = append(fields, Field{Path: path, Kind: "unknown"})
			continue
		}

		kind := memberShape.Type
		if len(memberShape.Enum) > 0 {
			kind = "enum"
		}

		fields = append(fields, Field{Path: path, Kind: kind})

		if memberShape.Type == "structure" {
			fields = append(fields, flattenShape(model, ref.Shape, path, depth+1)...)
		}
	}

	return fields
}

var botocoreDataDir string

func findModelPath(serviceName string) (string, error) {
	dir, err := getBotocoreDataDir()
	if err != nil {
		return "", err
	}

	svcDir := filepath.Join(dir, serviceName)
	entries, err := os.ReadDir(svcDir)
	if err != nil {
		return "", fmt.Errorf("service %q not found in botocore data", serviceName)
	}

	var latest string
	for _, e := range entries {
		if e.IsDir() && e.Name() > latest {
			latest = e.Name()
		}
	}
	if latest == "" {
		return "", fmt.Errorf("no API version found for %q", serviceName)
	}

	return filepath.Join(svcDir, latest, "service-2.json"), nil
}

func getBotocoreDataDir() (string, error) {
	if botocoreDataDir != "" {
		return botocoreDataDir, nil
	}

	if env := os.Getenv("BOTOCORE_DATA"); env != "" {
		botocoreDataDir = env
		return botocoreDataDir, nil
	}

	return "", errors.New("botocore data dir not set (call awsmeta.SetDataDir or set BOTOCORE_DATA)")
}
