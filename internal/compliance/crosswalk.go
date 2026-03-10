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
	"github.com/sufield/stave/internal/pkg/fp"
)

// Framework is a validated, normalized compliance framework identifier.
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

// ParseFramework validates and normalizes a raw string into a Framework.
func ParseFramework(s string) (Framework, error) {
	f := Framework(normalizeFramework(s))
	if _, ok := supportedFrameworks[f]; !ok {
		return "", fmt.Errorf(
			"unsupported compliance framework %q (use %s)", s,
			strings.Join(FrameworkStrings(SupportedFrameworks()), ", "),
		)
	}
	return f, nil
}

// SupportedFrameworks returns supported framework identifiers in sorted order.
func SupportedFrameworks() []Framework {
	return []Framework{
		FrameworkCISAWS,
		FrameworkNIST,
		FrameworkPCIDSS,
		FrameworkSOC2,
	}
}

type controlCrosswalkFile struct {
	Version string                                `yaml:"version"`
	Checks  map[string][]securityaudit.ControlRef `yaml:"checks"`
}

// CrosswalkResolution is the normalized control mapping snapshot for audit output.
type CrosswalkResolution struct {
	ByCheck        map[string][]securityaudit.ControlRef
	MissingChecks  []string
	ResolutionJSON []byte
}

type resolutionOutput struct {
	SchemaVersion string                                `json:"schema_version"`
	Frameworks    []string                              `json:"frameworks"`
	Checks        map[string][]securityaudit.ControlRef `json:"checks"`
	Missing       []string                              `json:"missing"`
	GeneratedAt   string                                `json:"generated_at"`
}

// ResolveControlCrosswalk resolves a crosswalk mapping from raw YAML bytes.
func ResolveControlCrosswalk(
	raw []byte,
	complianceFrameworks []string,
	checkIDs []string,
	now time.Time,
) (CrosswalkResolution, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	var parsed controlCrosswalkFile
	if decodeErr := decoder.Decode(&parsed); decodeErr != nil {
		return CrosswalkResolution{}, fmt.Errorf("parse crosswalk yaml: %w", decodeErr)
	}
	if strings.TrimSpace(parsed.Version) == "" {
		return CrosswalkResolution{}, fmt.Errorf("crosswalk version is required")
	}
	if len(parsed.Checks) == 0 {
		return CrosswalkResolution{}, fmt.Errorf("crosswalk checks section is empty")
	}

	selected, err := resolveFrameworkSet(complianceFrameworks)
	if err != nil {
		return CrosswalkResolution{}, err
	}
	allowed := fp.ToSet(selected)

	byCheck := make(map[string][]securityaudit.ControlRef, len(checkIDs))
	missing := make([]string, 0)
	for _, checkID := range checkIDs {
		filtered, filterErr := filterRefs(checkID, parsed.Checks[checkID], allowed)
		if filterErr != nil {
			return CrosswalkResolution{}, filterErr
		}

		slices.SortFunc(filtered, func(a, b securityaudit.ControlRef) int {
			if n := cmp.Compare(a.Framework, b.Framework); n != 0 {
				return n
			}
			return cmp.Compare(a.ControlID, b.ControlID)
		})
		byCheck[checkID] = filtered
		if len(filtered) == 0 {
			missing = append(missing, checkID)
		}
	}

	slices.Sort(missing)
	resolution := resolutionOutput{
		SchemaVersion: string(kernel.SchemaCrosswalkResolution),
		Frameworks:    FrameworkStrings(selected),
		Checks:        byCheck,
		Missing:       missing,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
	}
	resolutionJSON, err := json.MarshalIndent(resolution, "", "  ")
	if err != nil {
		return CrosswalkResolution{}, fmt.Errorf("marshal crosswalk resolution: %w", err)
	}

	return CrosswalkResolution{
		ByCheck:        byCheck,
		MissingChecks:  missing,
		ResolutionJSON: append(resolutionJSON, '\n'),
	}, nil
}

func resolveFrameworkSet(raw []string) ([]Framework, error) {
	if len(raw) == 0 {
		return SupportedFrameworks(), nil
	}
	seen := make(map[Framework]struct{})
	var out []Framework
	for _, value := range raw {
		for token := range strings.SplitSeq(value, ",") {
			f, err := ParseFramework(token)
			if err != nil {
				return nil, err
			}
			if _, ok := seen[f]; !ok {
				seen[f] = struct{}{}
				out = append(out, f)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

func filterRefs(checkID string, refs []securityaudit.ControlRef, allowed map[Framework]struct{}) ([]securityaudit.ControlRef, error) {
	out := make([]securityaudit.ControlRef, 0, len(refs))
	for _, ref := range refs {
		f := Framework(normalizeFramework(ref.Framework))
		if _, ok := allowed[f]; !ok {
			continue
		}
		controlID := strings.TrimSpace(ref.ControlID)
		rationale := strings.TrimSpace(ref.Rationale)
		if controlID == "" || rationale == "" {
			return nil, fmt.Errorf("crosswalk entry %s has empty control_id/rationale", checkID)
		}
		out = append(out, securityaudit.ControlRef{
			Framework: string(f),
			ControlID: controlID,
			Rationale: rationale,
		})
	}
	return out, nil
}

func normalizeFramework(value string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_")
}

// FrameworkStrings converts a slice of Framework values to their string representations.
func FrameworkStrings(fs []Framework) []string {
	return fp.Map(fs, func(f Framework) string { return string(f) })
}
