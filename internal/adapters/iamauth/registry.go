// Package iamauth reads IAM authorization reference data from the
// AWS service reference API (servicereference.us-east-1.amazonaws.com).
// It provides per-service registries of valid actions, condition keys,
// and resource types with ARN formats. No AWS credentials required.
package iamauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ServiceRef holds the parsed authorization reference for one service.
type ServiceRef struct {
	Name          string         `json:"Name"`
	Actions       []Action       `json:"Actions"`
	ConditionKeys []ConditionKey `json:"ConditionKeys"`
	Resources     []ResourceType `json:"Resources"`
	Operations    []Operation    `json:"Operations,omitempty"`
	Version       string         `json:"Version"`
}

// Action holds one IAM action's authorization metadata.
type Action struct {
	Name                string           `json:"Name"`
	ActionConditionKeys []string         `json:"ActionConditionKeys"`
	Annotations         ActionAnnotation `json:"Annotations"`
	Resources           []ActionResource `json:"Resources"`
}

// ActionAnnotation holds access-level classification.
type ActionAnnotation struct {
	Properties ActionProperties `json:"Properties"`
}

// ActionProperties classifies the access level.
type ActionProperties struct {
	IsList                 bool `json:"IsList"`
	IsPermissionManagement bool `json:"IsPermissionManagement"`
	IsTaggingOnly          bool `json:"IsTaggingOnly"`
	IsWrite                bool `json:"IsWrite"`
}

// AccessLevel returns the human-readable access level.
func (p ActionProperties) AccessLevel() string {
	switch {
	case p.IsPermissionManagement:
		return "Permissions management"
	case p.IsWrite:
		return "Write"
	case p.IsList:
		return "List"
	case p.IsTaggingOnly:
		return "Tagging"
	default:
		return "Read"
	}
}

// ActionResource is a resource type referenced by an action.
type ActionResource struct {
	Name string `json:"Name"`
}

// ConditionKey holds one condition key's metadata.
type ConditionKey struct {
	Name  string   `json:"Name"`
	Types []string `json:"Types"`
}

// ResourceType holds one resource type's ARN format and condition keys.
type ResourceType struct {
	Name          string   `json:"Name"`
	ARNFormats    []string `json:"ARNFormats"`
	ConditionKeys []string `json:"ConditionKeys"`
}

// Operation maps an API call to its authorized IAM actions.
type Operation struct {
	Name              string             `json:"Name"`
	AuthorizedActions []AuthorizedAction `json:"AuthorizedActions"`
}

// AuthorizedAction is an IAM action required by an operation,
// possibly in a different service (e.g. iam:PassRole).
type AuthorizedAction struct {
	Name    string              `json:"Name"`
	Service string              `json:"Service"`
	Context map[string][]string `json:"Context,omitempty"`
}

// IndexEntry is one service in the root index.
type IndexEntry struct {
	Service  string `json:"service"`
	URL      string `json:"url"`
	Modified int64  `json:"modified"`
}

var dataDir string

// SetDataDir sets the directory containing per-service JSON files
// fetched by geniamdata. Callers must set this before calling Load.
func SetDataDir(dir string) { dataDir = dir }

// Load reads and parses the service reference JSON for the given
// service prefix. Returns (nil, nil) if the service file doesn't exist.
func Load(service string) (*ServiceRef, error) {
	dir, err := getDataDir()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, service+".json")
	data, err := os.ReadFile(path) //nolint:gosec // path derived from configured data dir
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read iamauth %s: %w", service, err)
	}

	var ref ServiceRef
	if err := json.Unmarshal(data, &ref); err != nil {
		return nil, fmt.Errorf("parse iamauth %s: %w", service, err)
	}
	return &ref, nil
}

// LoadIndex reads the index file (index.json) from the data directory.
func LoadIndex() ([]IndexEntry, error) {
	dir, err := getDataDir()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filepath.Join(dir, "index.json")) //nolint:gosec // path derived from configured data dir
	if err != nil {
		return nil, fmt.Errorf("read iamauth index: %w", err)
	}

	var index []IndexEntry
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("parse iamauth index: %w", err)
	}
	return index, nil
}

// ActionRegistry provides action validation for a loaded service.
type ActionRegistry struct {
	service string
	actions map[string]bool
}

// NewActionRegistry builds an action lookup from a loaded ServiceRef.
func NewActionRegistry(ref *ServiceRef) *ActionRegistry {
	r := &ActionRegistry{
		service: ref.Name,
		actions: make(map[string]bool, len(ref.Actions)),
	}
	for _, a := range ref.Actions {
		r.actions[strings.ToLower(a.Name)] = true
	}
	return r
}

// Valid reports whether the action name is valid for this service.
func (r *ActionRegistry) Valid(action string) bool {
	return r.actions[strings.ToLower(action)]
}

// All returns all valid action names, sorted.
func (r *ActionRegistry) All() []string {
	out := make([]string, 0, len(r.actions))
	for a := range r.actions {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// ConditionKeyRegistry provides condition key validation.
type ConditionKeyRegistry struct {
	keys     map[string]string // lowercase key → type
	patterns []string          // parameterized key prefixes
}

// NewConditionKeyRegistry builds a condition key lookup.
func NewConditionKeyRegistry(ref *ServiceRef) *ConditionKeyRegistry {
	r := &ConditionKeyRegistry{
		keys: make(map[string]string, len(ref.ConditionKeys)),
	}
	for _, ck := range ref.ConditionKeys {
		lower := strings.ToLower(ck.Name)
		typ := "String"
		if len(ck.Types) > 0 {
			typ = ck.Types[0]
		}
		r.keys[lower] = typ

		if before, _, ok := strings.Cut(lower, "${"); ok {
			r.patterns = append(r.patterns, before)
		}
	}
	return r
}

// Valid reports whether the condition key is valid for this service.
func (r *ConditionKeyRegistry) Valid(key string) bool {
	lower := strings.ToLower(key)
	if _, ok := r.keys[lower]; ok {
		return true
	}
	for _, prefix := range r.patterns {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// KeyType returns the type of a condition key, or "" if unknown.
func (r *ConditionKeyRegistry) KeyType(key string) string {
	return r.keys[strings.ToLower(key)]
}

// All returns all condition key names, sorted.
func (r *ConditionKeyRegistry) All() []string {
	out := make([]string, 0, len(r.keys))
	for k := range r.keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ResourceTypeRegistry provides resource type and ARN validation.
type ResourceTypeRegistry struct {
	resources map[string]ResourceType
}

// NewResourceTypeRegistry builds a resource type lookup.
func NewResourceTypeRegistry(ref *ServiceRef) *ResourceTypeRegistry {
	r := &ResourceTypeRegistry{
		resources: make(map[string]ResourceType, len(ref.Resources)),
	}
	for _, rt := range ref.Resources {
		r.resources[strings.ToLower(rt.Name)] = rt
	}
	return r
}

// Valid reports whether the resource type name exists for this service.
func (r *ResourceTypeRegistry) Valid(name string) bool {
	_, ok := r.resources[strings.ToLower(name)]
	return ok
}

// ARNFormats returns the ARN format patterns for a resource type.
func (r *ResourceTypeRegistry) ARNFormats(name string) []string {
	rt, ok := r.resources[strings.ToLower(name)]
	if !ok {
		return nil
	}
	out := make([]string, len(rt.ARNFormats))
	copy(out, rt.ARNFormats)
	return out
}

// All returns all resource type names, sorted.
func (r *ResourceTypeRegistry) All() []string {
	out := make([]string, 0, len(r.resources))
	for name := range r.resources {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ActionConditionKeys returns the condition keys applicable to a
// specific action. Returns nil if the action is unknown.
func ActionConditionKeys(ref *ServiceRef, action string) []string {
	lower := strings.ToLower(action)
	for _, a := range ref.Actions {
		if strings.ToLower(a.Name) == lower {
			out := make([]string, len(a.ActionConditionKeys))
			copy(out, a.ActionConditionKeys)
			return out
		}
	}
	return nil
}

// ActionResources returns the resource types an action operates on.
func ActionResources(ref *ServiceRef, action string) []string {
	lower := strings.ToLower(action)
	for _, a := range ref.Actions {
		if strings.ToLower(a.Name) == lower {
			out := make([]string, 0, len(a.Resources))
			for _, r := range a.Resources {
				out = append(out, r.Name)
			}
			return out
		}
	}
	return nil
}

// DependentActions returns cross-service actions required by an
// operation (e.g. iam:PassRole required by lambda:CreateFunction).
func DependentActions(ref *ServiceRef, operation string) []AuthorizedAction {
	lower := strings.ToLower(operation)
	for _, op := range ref.Operations {
		if strings.ToLower(op.Name) != lower {
			continue
		}
		var deps []AuthorizedAction
		for _, aa := range op.AuthorizedActions {
			if aa.Service != ref.Name {
				deps = append(deps, aa)
			}
		}
		return deps
	}
	return nil
}

func getDataDir() (string, error) {
	if dataDir != "" {
		return dataDir, nil
	}
	if env := os.Getenv("IAMAUTH_DATA"); env != "" {
		dataDir = env
		return dataDir, nil
	}
	return "", errors.New("iamauth data dir not set (call iamauth.SetDataDir or set IAMAUTH_DATA)")
}
