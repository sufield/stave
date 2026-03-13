package compliance

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/securityaudit"
)

// Framework represents a normalized compliance standard (e.g., "nist_800_53").
type Framework string

const (
	FrameworkNIST   Framework = "nist_800_53"
	FrameworkCISAWS Framework = "cis_aws_v1.4.0"
	FrameworkSOC2   Framework = "soc2"
	FrameworkPCIDSS Framework = "pci_dss_v3.2.1"
)

var supportedFrameworks = map[Framework]struct{}{
	FrameworkNIST:   {},
	FrameworkCISAWS: {},
	FrameworkSOC2:   {},
	FrameworkPCIDSS: {},
}

// ParseFramework validates and normalizes a raw string into a Framework type.
func ParseFramework(s string) (Framework, error) {
	f := Framework(normalize(s))
	if _, ok := supportedFrameworks[f]; !ok {
		supported := strings.Join(FrameworkStrings(SupportedFrameworks()), ", ")
		return "", fmt.Errorf("unsupported compliance framework %q (use: %s)", s, supported)
	}
	return f, nil
}

// SupportedFrameworks returns the list of frameworks recognized by the system, sorted alphabetically.
func SupportedFrameworks() []Framework {
	return []Framework{FrameworkCISAWS, FrameworkNIST, FrameworkPCIDSS, FrameworkSOC2}
}

// CrosswalkResolution captures the mapping between internal audit checks and external controls.
type CrosswalkResolution struct {
	ByCheck        map[string][]securityaudit.ControlRef
	MissingChecks  []string
	ResolutionJSON []byte
}

// ResolveControlCrosswalk parses raw YAML mapping data and filters it against the requested frameworks.
func ResolveControlCrosswalk(
	raw []byte,
	frameworkFilter []string,
	expectedCheckIDs []string,
	now time.Time,
) (CrosswalkResolution, error) {
	var parsed struct {
		Version string                                `yaml:"version"`
		Checks  map[string][]securityaudit.ControlRef `yaml:"checks"`
	}

	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&parsed); err != nil {
		return CrosswalkResolution{}, fmt.Errorf("failed to parse crosswalk yaml: %w", err)
	}

	if strings.TrimSpace(parsed.Version) == "" {
		return CrosswalkResolution{}, fmt.Errorf("crosswalk 'version' is required")
	}

	selected, err := resolveFrameworks(frameworkFilter)
	if err != nil {
		return CrosswalkResolution{}, err
	}

	allowedSet := make(map[Framework]struct{}, len(selected))
	for _, f := range selected {
		allowedSet[f] = struct{}{}
	}

	byCheck := make(map[string][]securityaudit.ControlRef, len(expectedCheckIDs))
	var missing []string

	for _, id := range expectedCheckIDs {
		refs, filterErr := filterAndNormalizeRefs(id, parsed.Checks[id], allowedSet)
		if filterErr != nil {
			return CrosswalkResolution{}, filterErr
		}

		if len(refs) == 0 {
			missing = append(missing, id)
			byCheck[id] = []securityaudit.ControlRef{}
			continue
		}

		slices.SortFunc(refs, func(a, b securityaudit.ControlRef) int {
			return cmp.Or(
				cmp.Compare(a.Framework, b.Framework),
				cmp.Compare(a.ControlID, b.ControlID),
			)
		})
		byCheck[id] = refs
	}

	slices.Sort(missing)

	output := struct {
		SchemaVersion kernel.Schema                         `json:"schema_version"`
		Frameworks    []string                              `json:"frameworks"`
		Checks        map[string][]securityaudit.ControlRef `json:"checks"`
		Missing       []string                              `json:"missing"`
		GeneratedAt   string                                `json:"generated_at"`
	}{
		SchemaVersion: kernel.SchemaCrosswalkResolution,
		Frameworks:    FrameworkStrings(selected),
		Checks:        byCheck,
		Missing:       missing,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
	}

	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return CrosswalkResolution{}, fmt.Errorf("failed to marshal crosswalk resolution: %w", err)
	}

	return CrosswalkResolution{
		ByCheck:        byCheck,
		MissingChecks:  missing,
		ResolutionJSON: append(jsonBytes, '\n'),
	}, nil
}

// --- Internal Helpers ---

func resolveFrameworks(raw []string) ([]Framework, error) {
	if len(raw) == 0 {
		return SupportedFrameworks(), nil
	}

	seen := make(map[Framework]struct{})
	var out []Framework

	for _, r := range raw {
		for token := range strings.SplitSeq(r, ",") {
			f, err := ParseFramework(token)
			if err != nil {
				return nil, err
			}
			if _, exists := seen[f]; !exists {
				seen[f] = struct{}{}
				out = append(out, f)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

func filterAndNormalizeRefs(checkID string, refs []securityaudit.ControlRef, allowed map[Framework]struct{}) ([]securityaudit.ControlRef, error) {
	out := make([]securityaudit.ControlRef, 0, len(refs))
	for _, r := range refs {
		f := Framework(normalize(r.Framework))
		if _, ok := allowed[f]; !ok {
			continue
		}

		cID := strings.TrimSpace(r.ControlID)
		rat := strings.TrimSpace(r.Rationale)
		if cID == "" || rat == "" {
			return nil, fmt.Errorf("crosswalk entry for %q has empty control_id or rationale", checkID)
		}

		out = append(out, securityaudit.ControlRef{
			Framework: string(f),
			ControlID: cID,
			Rationale: rat,
		})
	}
	return out, nil
}

func normalize(v string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(v)), "-", "_")
}

// FrameworkStrings converts a slice of Framework to a slice of strings.
func FrameworkStrings(fs []Framework) []string {
	res := make([]string, len(fs))
	for i, f := range fs {
		res[i] = string(f)
	}
	return res
}
