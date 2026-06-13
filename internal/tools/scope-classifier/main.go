//go:build ignore

// Command scope-classifier walks every control YAML in the catalog
// and proposes a `scope` classification (atomic | compound) per the
// heuristics locked in aws-compound-control-authoring-plan.md.
//
// Usage:
//
//	go run ./internal/tools/scope-classifier/main.go \
//	    -controls ./controls \
//	    -report ./docs/control-classification-proposal.md
//
// The classifier does NOT modify control YAMLs. It produces a
// proposal report the operator reviews; the migration commit (a
// future iteration) applies the reviewed proposals.
//
// Heuristics in priority order:
//
//  1. archetype == "ghost-reference" → compound
//     (ghost-reference is inherently cross-resource — the predicate
//     reasons about whether a referenced asset exists in another
//     part of the snapshot)
//
//  2. len(applicable_asset_types) > 1 → compound
//     (predicate fires across multiple asset types — same
//     predicate evaluated per type, requiring cross-type vocabulary)
//
//  3. predicate references a compound-observation-field path
//     (identity.escalation., identity.nep., identity.blastradius.,
//     identity.chain., etc.) → compound
//     (the cross-asset reasoning lives in the observation
//     extractor that produces these pre-computed fields; the
//     predicate evaluates the result. NEP, BLASTRADIUS, ESCALATE,
//     CHAIN families all classify here.)
//
//  4. otherwise → atomic
//     (single-asset property check; the territory framework
//     scanners cover well.)
//
// False positives from heuristic 2 (multi-asset-type controls
// that are actually polymorphic rather than compound) are
// captured in controls/_scope-overrides.yaml with rationale.
// Add new compound-field-path prefixes below
// (compoundFieldPrefixes) when the observation contract grows
// additional cross-asset computed fields.
package main

import (
	"cmp"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// proposal is one control's classification result.
type proposal struct {
	Path      string // absolute path to the YAML file
	Rel       string // path relative to the controls root
	ID        string // control_id
	Domain    string // first path component under controls/ (e.g. "iam", "s3")
	Existing  string // explicit `scope` value in the YAML, if any
	Proposed  string // classifier's proposal (heuristic-derived; overrides not yet applied)
	Override  string // override value from _scope-overrides.yaml, if any
	Final     string // Override when set, else Proposed
	Rationale string // override rationale, if any
	Heuristic string // which rule fired
}

// overridesFile mirrors the YAML shape of controls/_scope-overrides.yaml.
type overridesFile struct {
	Overrides []overrideEntry `yaml:"overrides"`
}

type overrideEntry struct {
	ControlID string `yaml:"control_id"`
	Scope     string `yaml:"scope"`
	Rationale string `yaml:"rationale"`
}

// controlYAML is the subset of fields the classifier reads.
type controlYAML struct {
	ID                   string         `yaml:"id"`
	Archetype            string         `yaml:"archetype"`
	Scope                string         `yaml:"scope"`
	ApplicableAssetTypes []string       `yaml:"applicable_asset_types"`
	UnsafePredicate      map[string]any `yaml:"unsafe_predicate"`
}

// compoundFieldPrefixes are observation-field path prefixes that
// indicate cross-asset reasoning. The Stave observation extractor
// pre-computes cross-asset properties (e.g.,
// identity.escalation.passrole.present is true iff the principal
// has iam:PassRole on a role whose effective permissions exceed
// the principal's boundary — that determination walks the IAM
// graph). A predicate that references these fields is reasoning
// compound-shaped even when the structural form is a single-
// asset check.
//
// Add new prefixes here when the observation contract grows
// additional cross-asset computed fields.
var compoundFieldPrefixes = []string{
	// Privilege-escalation family — observation extractor's IAM-graph walk
	"identity.escalation.",
	// Net effective permissions — SCP + boundary + policies + denies + role chains
	"identity.nep.",
	// Reachable-resource counts + cross-account reach
	"identity.blastradius.",
	// Role-level cross-asset facets (subset of BLASTRADIUS computation)
	"identity.role.reachable_resources",
	"identity.role.sensitive_resource",
	"identity.role.assume_chain",
	"identity.role.cross_account_trust",
	"identity.role.blast_radius_scope",
	"identity.role.cross_env",
	// User-level cross-asset facets
	"identity.user.reachable_resources",
	"identity.user.sensitive_resource",
	// Trust-policy composition — extractor analyses trust + principal account + target permissions
	"identity.trust_policy.",
	"identity.trust.oidc.",
	"identity.federation.",
	// Role-chain analysis
	"identity.chain.",
	// SSO / Identity Center — aggregates across IdPs + users + permission sets
	"identity.sso.",
	// IAM-account-level federation hygiene (account-wide aggregation of federation use)
	"iam.federation_",
	// Resource-side NEP — walks the IAM graph from every principal toward the resource
	"resource.nep.",
}

func main() {
	var (
		root   string
		report string
	)
	flag.StringVar(&root, "controls", "controls", "path to controls root")
	flag.StringVar(&report, "report", "docs/control-classification-proposal.md",
		"path to write the proposal report (empty = stdout)")
	flag.Parse()

	overrides, err := loadOverrides(filepath.Join(root, "_scope-overrides.yaml"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "load overrides: %v\n", err)
		os.Exit(1)
	}

	var proposals []proposal
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		base := d.Name()
		if !strings.HasPrefix(base, "CTL.") || !strings.HasSuffix(base, ".yaml") {
			return nil
		}
		p, err := classifyOne(root, path)
		if err != nil {
			return fmt.Errorf("classify %s: %w", path, err)
		}
		// Apply override if present, then derive Final.
		if ov, ok := overrides[p.ID]; ok {
			p.Override = ov.Scope
			p.Rationale = ov.Rationale
			p.Final = ov.Scope
		} else {
			p.Final = p.Proposed
		}
		proposals = append(proposals, p)
		return nil
	})
	if walkErr != nil {
		fmt.Fprintf(os.Stderr, "walk error: %v\n", walkErr)
		os.Exit(1)
	}

	slices.SortFunc(proposals, func(a, b proposal) int {
		return cmp.Compare(a.Rel, b.Rel)
	})

	out, err := renderReport(proposals)
	if err != nil {
		fmt.Fprintf(os.Stderr, "render: %v\n", err)
		os.Exit(1)
	}

	if report == "" {
		fmt.Print(out)
		return
	}
	if err := os.MkdirAll(filepath.Dir(report), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(report, []byte(out), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d proposals)\n", report, len(proposals))
}

// classifyOne reads one YAML, applies the heuristics, returns the
// proposal. Doesn't mutate the file.
func classifyOne(root, path string) (proposal, error) {
	rel, _ := filepath.Rel(root, path)
	raw, err := os.ReadFile(path)
	if err != nil {
		return proposal{}, err
	}
	var y controlYAML
	if err := yaml.Unmarshal(raw, &y); err != nil {
		return proposal{}, err
	}

	p := proposal{
		Path:     path,
		Rel:      rel,
		ID:       y.ID,
		Domain:   topDomain(rel),
		Existing: strings.TrimSpace(y.Scope),
	}

	switch {
	case strings.TrimSpace(y.Archetype) == "ghost-reference":
		p.Proposed = "compound"
		p.Heuristic = "archetype=ghost-reference"
	case len(y.ApplicableAssetTypes) > 1:
		p.Proposed = "compound"
		p.Heuristic = fmt.Sprintf("applicable_asset_types=%d", len(y.ApplicableAssetTypes))
	default:
		if matched := compoundFieldMatch(y.UnsafePredicate); matched != "" {
			p.Proposed = "compound"
			p.Heuristic = "predicate references " + matched + " (cross-asset observation field)"
		} else {
			p.Proposed = "atomic"
			p.Heuristic = "default (single asset, no compound signal)"
		}
	}
	return p, nil
}

// compoundFieldMatch walks the predicate AST and returns the
// first compoundFieldPrefixes match found in any rule's `field:`
// value. Empty string when no match. The predicate's wire shape
// is map[string]any with `any:` / `all:` keys holding []map of
// nested rules, and `field:` keys on leaf rules. Walk both.
func compoundFieldMatch(node map[string]any) string {
	if node == nil {
		return ""
	}
	if v, ok := node["field"].(string); ok {
		// Use Contains rather than HasPrefix: catalog YAMLs prefix
		// observation paths with `properties.` (e.g.
		// `properties.identity.escalation.passrole.present`).
		// The match needs to be substring-anywhere so we catch
		// the compound-signaling segment regardless of how the
		// catalog spells the outer prefix.
		for _, marker := range compoundFieldPrefixes {
			if strings.Contains(v, marker) {
				return marker
			}
		}
	}
	for _, key := range []string{"any", "all"} {
		raw, ok := node[key]
		if !ok {
			continue
		}
		items, ok := raw.([]any)
		if !ok {
			continue
		}
		for _, it := range items {
			child, ok := it.(map[string]any)
			if !ok {
				continue
			}
			if m := compoundFieldMatch(child); m != "" {
				return m
			}
		}
	}
	return ""
}

// topDomain extracts the first path component under controls/ —
// "iam", "s3", "cloudfront", etc. Used for the per-domain summary
// in the report.
func topDomain(rel string) string {
	before, _, _ := strings.Cut(rel, string(filepath.Separator))
	return before
}

// isTriageDomain reports whether the domain directory is one the
// canonical loader filters out. The strategic compound-share math
// should exclude these because they don't ship in the embedded
// catalog. Hardcoded list reflects the catalog convention at
// authoring time; revisit if the loader's filter set changes.
func isTriageDomain(domain string) bool {
	switch domain {
	case "_triage":
		return true
	}
	return false
}

// loadOverrides reads controls/_scope-overrides.yaml and returns
// a map keyed by control_id. Empty map when the file is absent —
// overrides are optional. Errors only on malformed content.
func loadOverrides(path string) (map[string]overrideEntry, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]overrideEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	var f overridesFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	out := make(map[string]overrideEntry, len(f.Overrides))
	for _, o := range f.Overrides {
		if o.ControlID == "" {
			continue
		}
		out[o.ControlID] = o
	}
	return out, nil
}

// renderReport produces the Markdown proposal report.
func renderReport(proposals []proposal) (string, error) {
	var b strings.Builder

	// Summary first.
	totals := map[string]int{}
	canonical := map[string]int{} // excludes _triage and other loader-filtered dirs
	perDomain := map[string]map[string]int{}
	disagreements := 0
	overridden := 0
	for _, p := range proposals {
		totals[p.Final]++
		if !isTriageDomain(p.Domain) {
			canonical[p.Final]++
		}
		if _, ok := perDomain[p.Domain]; !ok {
			perDomain[p.Domain] = map[string]int{}
		}
		perDomain[p.Domain][p.Final]++
		if p.Override != "" && p.Override != p.Proposed {
			overridden++
		}
		// Disagreement = the YAML's explicit `scope:` field
		// disagrees with the FINAL value (Override-applied).
		// An override that matches the YAML's explicit value
		// isn't a disagreement.
		if p.Existing != "" && p.Existing != p.Final {
			disagreements++
		}
	}
	canonicalTotal := canonical["atomic"] + canonical["compound"]

	fmt.Fprintln(&b, "# Control classification proposal")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Generated by `internal/tools/scope-classifier`. Walks every")
	fmt.Fprintln(&b, "`controls/**/CTL.*.yaml` and proposes a `scope` value")
	fmt.Fprintln(&b, "(`atomic` | `compound`) per the heuristics documented at the")
	fmt.Fprintln(&b, "top of `main.go`.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Summary")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "### Raw counts (every CTL.*.yaml the walker saw)")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Total controls classified:       **%d**\n", len(proposals))
	fmt.Fprintf(&b, "- Proposed atomic:                 **%d**\n", totals["atomic"])
	fmt.Fprintf(&b, "- Proposed compound:               **%d**\n", totals["compound"])
	if len(proposals) > 0 {
		fmt.Fprintf(&b, "- Raw compound share:              **%.2f%%**\n",
			float64(totals["compound"])/float64(len(proposals))*100)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "### Canonical counts (excludes `_triage/` and other loader-filtered dirs)")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "This is the denominator the strategic positioning math should")
	fmt.Fprintln(&b, "use — `make readme` reports the same canonical control count")
	fmt.Fprintln(&b, "(2,658 at audit time).")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Canonical controls classified:   **%d**\n", canonicalTotal)
	fmt.Fprintf(&b, "- Canonical atomic:                **%d**\n", canonical["atomic"])
	fmt.Fprintf(&b, "- Canonical compound:              **%d**\n", canonical["compound"])
	if canonicalTotal > 0 {
		fmt.Fprintf(&b, "- **Canonical compound share:      %.2f%%**\n",
			float64(canonical["compound"])/float64(canonicalTotal)*100)
	}
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Heuristic→override flips applied (`_scope-overrides.yaml`): **%d**\n", overridden)
	fmt.Fprintf(&b, "Disagreements with existing explicit `scope` (post-override): **%d**\n", disagreements)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Per-domain breakdown")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "| Domain | Atomic | Compound | Total |")
	fmt.Fprintln(&b, "|---|---:|---:|---:|")
	var domains []string
	for d := range perDomain {
		domains = append(domains, d)
	}
	slices.Sort(domains)
	for _, d := range domains {
		c := perDomain[d]
		fmt.Fprintf(&b, "| %s | %d | %d | %d |\n",
			d, c["atomic"], c["compound"], c["atomic"]+c["compound"])
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Compound proposals — review every entry")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Per the plan's review discipline, every proposed `compound`")
	fmt.Fprintln(&b, "needs human confirmation. Disagree? Add an entry to")
	fmt.Fprintln(&b, "`controls/_scope-overrides.yaml`.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "| Control ID | Path | Heuristic |")
	fmt.Fprintln(&b, "|---|---|---|")
	for _, p := range proposals {
		if p.Proposed != "compound" {
			continue
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", p.ID, p.Rel, p.Heuristic)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Disagreements (existing explicit scope ≠ proposal)")
	fmt.Fprintln(&b)
	if disagreements == 0 {
		fmt.Fprintln(&b, "_None._")
	} else {
		fmt.Fprintln(&b, "| Control ID | Path | Existing | Proposed | Heuristic |")
		fmt.Fprintln(&b, "|---|---|---|---|---|")
		for _, p := range proposals {
			if p.Existing == "" || p.Existing == p.Proposed {
				continue
			}
			fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s | %s |\n",
				p.ID, p.Rel, p.Existing, p.Proposed, p.Heuristic)
		}
	}
	fmt.Fprintln(&b)
	return b.String(), nil
}
