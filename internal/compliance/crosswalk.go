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

	"github.com/sufield/stave/internal/core/kernel"
)

// Framework represents a normalized compliance standard (e.g., "nist_800_53").
type Framework string

// ControlRef is a reference to an external compliance control.
type ControlRef struct {
	Framework Framework `json:"framework" yaml:"framework"`
	ControlID string    `json:"control_id" yaml:"control_id"`
	Rationale string    `json:"rationale" yaml:"rationale"`
}

// Supported compliance framework identifiers.
const (
	FrameworkNIST     Framework = "nist_800_53"
	FrameworkNISTR5   Framework = "nist_800_53_r5"
	FrameworkCISAWS   Framework = "cis_aws_v1.4.0"
	FrameworkCISAWSV3 Framework = "cis_aws_v3.0"
	FrameworkSOC2     Framework = "soc2"
	FrameworkPCIDSS   Framework = "pci_dss_v3.2.1"
	FrameworkPCIDSSV4 Framework = "pci_dss_v4.0"
	FrameworkHIPAA    Framework = "hipaa"
	FrameworkFedRAMP  Framework = "fedramp_moderate"
	FrameworkGDPR     Framework = "gdpr"
	FrameworkFFIEC    Framework = "ffiec"
	FrameworkISO27001 Framework = "iso_27001_2022"
	FrameworkNISTCSF  Framework = "nist_csf_2.0"
)

var supportedFrameworks = map[Framework]struct{}{
	FrameworkNIST:     {},
	FrameworkNISTR5:   {},
	FrameworkCISAWS:   {},
	FrameworkCISAWSV3: {},
	FrameworkSOC2:     {},
	FrameworkPCIDSS:   {},
	FrameworkPCIDSSV4: {},
	FrameworkHIPAA:    {},
	FrameworkFedRAMP:  {},
	FrameworkGDPR:     {},
	FrameworkFFIEC:    {},
	FrameworkISO27001: {},
	FrameworkNISTCSF:  {},
}

// frameworkAliases maps human-friendly variant identifiers to the
// canonical framework key. Aliases let "iso_27001" stand in for the
// versioned "iso_27001_2022" canonical id without forcing every
// crosswalk author to spell the version. Add new entries when a
// canonical id changes (versioning) so existing data keeps loading.
var frameworkAliases = map[Framework]Framework{
	"iso_27001": FrameworkISO27001,
}

// ParseFramework validates and normalizes a raw string into a Framework type.
func ParseFramework(s string) (Framework, error) {
	return canonicalizeFramework(s)
}

// canonicalizeFramework applies the project's framework name normalization:
// lowercase + dash/space → underscore, then alias resolution against
// frameworkAliases, then membership check against supportedFrameworks.
//
// Centralizes the rule so ParseFramework and filterAndNormalizeRefs
// share one definition. A typo or missing-alias bug used to require
// fixing both call sites; now there is one.
func canonicalizeFramework(s string) (Framework, error) {
	f := Framework(normalize(s))
	if alias, ok := frameworkAliases[f]; ok {
		f = alias
	}
	if _, ok := supportedFrameworks[f]; !ok {
		supported := strings.Join(FrameworkStrings(SupportedFrameworks()), ", ")
		return "", fmt.Errorf("unsupported compliance framework %q (use: %s)", s, supported)
	}
	return f, nil
}

// SupportedFrameworks returns the list of frameworks recognized by
// the system, sorted alphabetically. Derived dynamically from the
// supportedFrameworks map so adding a new framework constant + map
// entry is the only change needed; the previous shape kept a
// hand-maintained slice and silently went stale when authors forgot
// to mirror the new entry here.
func SupportedFrameworks() []Framework {
	out := make([]Framework, 0, len(supportedFrameworks))
	for f := range supportedFrameworks {
		out = append(out, f)
	}
	slices.Sort(out)
	return out
}

// CrosswalkResolution captures the mapping between internal audit
// checks and external controls.
//
// MissingChecks vs FilteredChecks: the earlier shape collapsed both
// "no crosswalk mapping defined for this control" and "mappings
// existed but every one was excluded by --frameworks" into the same
// MissingChecks bucket, hiding genuine catalog gaps from operators
// who passed a framework filter. They are now distinct:
//   - MissingChecks  → no crosswalk mapping at all
//   - FilteredChecks → mapping existed; all entries excluded by
//     the framework filter
type CrosswalkResolution struct {
	ByCheck        map[kernel.ControlID][]ControlRef
	MissingChecks  []kernel.ControlID
	FilteredChecks []kernel.ControlID
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
		Version string                  `yaml:"version"`
		Checks  map[string][]ControlRef `yaml:"checks"`
	}

	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&parsed); err != nil {
		return CrosswalkResolution{}, fmt.Errorf("failed to parse crosswalk yaml: %w", err)
	}

	if strings.TrimSpace(parsed.Version) == "" {
		parsed.Version = "1.0"
	}

	selected, err := resolveFrameworks(frameworkFilter)
	if err != nil {
		return CrosswalkResolution{}, err
	}

	allowedSet := make(map[Framework]struct{}, len(selected))
	for _, f := range selected {
		allowedSet[f] = struct{}{}
	}

	byCheck := make(map[kernel.ControlID][]ControlRef, len(expectedCheckIDs))
	var missing []kernel.ControlID
	var filtered []kernel.ControlID

	for _, id := range expectedCheckIDs {
		cid := kernel.ControlID(id)
		rawRefs := parsed.Checks[id]
		refs, filterErr := filterAndNormalizeRefs(id, rawRefs, allowedSet)
		if filterErr != nil {
			return CrosswalkResolution{}, filterErr
		}

		if len(refs) == 0 {
			// Distinguish "no mapping at all" from "mapping
			// existed but all entries were excluded by the
			// --frameworks filter". The latter is operator
			// noise filtered by intent; only the former
			// represents a catalog gap.
			if len(rawRefs) == 0 {
				missing = append(missing, cid)
			} else {
				filtered = append(filtered, cid)
			}
			byCheck[cid] = []ControlRef{}
			continue
		}

		slices.SortFunc(refs, func(a, b ControlRef) int {
			return cmp.Or(
				cmp.Compare(string(a.Framework), string(b.Framework)),
				cmp.Compare(a.ControlID, b.ControlID),
			)
		})
		byCheck[cid] = refs
	}

	slices.SortFunc(missing, cmp.Compare[kernel.ControlID])
	slices.SortFunc(filtered, cmp.Compare[kernel.ControlID])

	checksOut := make(map[string][]ControlRef, len(byCheck))
	for k, v := range byCheck {
		checksOut[string(k)] = v
	}
	missingOut := make([]string, len(missing))
	for i, m := range missing {
		missingOut[i] = string(m)
	}
	filteredOut := make([]string, len(filtered))
	for i, f := range filtered {
		filteredOut[i] = string(f)
	}

	output := struct {
		SchemaVersion kernel.Schema           `json:"schema_version"`
		Frameworks    []string                `json:"frameworks"`
		Checks        map[string][]ControlRef `json:"checks"`
		Missing       []string                `json:"missing"`
		Filtered      []string                `json:"filtered"`
		GeneratedAt   string                  `json:"generated_at"`
	}{
		SchemaVersion: kernel.SchemaCrosswalkResolution,
		Frameworks:    FrameworkStrings(selected),
		Checks:        checksOut,
		Missing:       missingOut,
		Filtered:      filteredOut,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
	}

	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return CrosswalkResolution{}, fmt.Errorf("failed to marshal crosswalk resolution: %w", err)
	}

	return CrosswalkResolution{
		ByCheck:        byCheck,
		MissingChecks:  missing,
		FilteredChecks: filtered,
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
			// Skip empty tokens left by trailing commas, double
			// commas, or whitespace-only entries — these are
			// common operator typos (`--frameworks=soc2,`) and
			// the strict shape used to surface as a confusing
			// "unsupported compliance framework \"\"" error
			// instead of just accepting the trimmed list.
			if strings.TrimSpace(token) == "" {
				continue
			}
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
	// Non-empty input that resolved to zero frameworks (e.g.
	// `--frameworks=,, ,`) silently fell through to "all
	// frameworks" semantics in the caller, which is the opposite of
	// what the operator asked for. Surface the empty-after-trim case
	// as an error so the typo is visible.
	if len(out) == 0 {
		return nil, fmt.Errorf("framework filter %v matched no known frameworks", raw)
	}
	slices.Sort(out)
	return out, nil
}

func filterAndNormalizeRefs(checkID string, refs []ControlRef, allowed map[Framework]struct{}) ([]ControlRef, error) {
	out := make([]ControlRef, 0, len(refs))
	for _, r := range refs {
		// A framework name that isn't in the global supported set is a
		// typo in the crosswalk file — surface it instead of silently
		// dropping the row, which used to make missing frameworks look
		// like missing controls. The user-filter step (`allowed`) is a
		// separate concern: a known framework that the operator filtered
		// out is correctly skipped.
		f, canonErr := canonicalizeFramework(string(r.Framework))
		if canonErr != nil {
			return nil, fmt.Errorf("crosswalk entry for %q references unknown framework %q: %w",
				checkID, r.Framework, canonErr)
		}

		// Validate body fields BEFORE the user-filter check. A blank
		// control_id or rationale in the crosswalk file is a typo
		// regardless of which framework the operator selected — the
		// previous shape only flagged it when the row's framework
		// happened to be allowed, so a malformed row in a filtered
		// framework hid until someone re-ran with that framework
		// enabled. Same rationale as the canonicalizeFramework check
		// above.
		cID := strings.TrimSpace(r.ControlID)
		rat := strings.TrimSpace(r.Rationale)
		if cID == "" || rat == "" {
			return nil, fmt.Errorf("crosswalk entry for %q has empty control_id or rationale", checkID)
		}

		if _, ok := allowed[f]; !ok {
			continue
		}

		out = append(out, ControlRef{
			Framework: f,
			ControlID: cID,
			Rationale: rat,
		})
	}
	return out, nil
}

func normalize(v string) string {
	// Lower-case + replace dashes AND spaces with underscores so a
	// framework name written as "PCI DSS v3.2.1" canonicalizes to
	// the same key as "pci_dss_v3.2.1". Without the space rule the
	// crosswalk silently treated the two as different frameworks
	// and the human-readable form never matched any registered
	// canonical name.
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, "-", "_")
	v = strings.ReplaceAll(v, " ", "_")
	return v
}

// FrameworkStrings converts a slice of Framework to a slice of strings.
func FrameworkStrings(fs []Framework) []string {
	res := make([]string, len(fs))
	for i, f := range fs {
		res[i] = string(f)
	}
	return res
}
