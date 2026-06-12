package capabilities

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
)

// Capability is a single user-facing record describing one thing
// Stave can check. The catalog aggregates the ~3,957 controls and
// ~585 chains into roughly 100-200 capability groups so users can
// browse and search by intent rather than by control ID.
//
// Three sources flow into the catalog:
//   - Control groups   (service + category buckets across controls)
//   - Compound chains  (chains/*.yaml)
//   - Operational      (hard-coded list of CLI features: readiness,
//     gaps, drift, validate, export-sir, etc.)
type Capability struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"` // "control_group" | "chain" | "operational"
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	UseWhen     string   `json:"use_when,omitempty"`
	Service     string   `json:"service,omitempty"`
	Category    string   `json:"category,omitempty"`
	AssetTypes  []string `json:"asset_types,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	ControlIDs  []string `json:"control_ids,omitempty"`
	ChainIDs    []string `json:"chain_ids,omitempty"`
	Keywords    []string `json:"keywords,omitempty"`
	ExampleCmd  string   `json:"example_command,omitempty"`
}

// Build aggregates the catalog from controls + chains + the
// hard-coded operational list. Pure function — no I/O, no globals.
func Build(controls []policy.ControlDefinition, chains []policy.ChainDefinition) []Capability {
	caps := make([]Capability, 0, 200)
	caps = append(caps, buildControlGroups(controls)...)
	caps = append(caps, buildChainCaps(chains)...)
	caps = append(caps, operationalCaps()...)
	slices.SortFunc(caps, func(a, b Capability) int {
		if a.Kind != b.Kind {
			return cmp.Compare(kindOrder(a.Kind), kindOrder(b.Kind))
		}
		if a.Service != b.Service {
			return cmp.Compare(a.Service, b.Service)
		}
		return cmp.Compare(a.Title, b.Title)
	})
	return caps
}

func kindOrder(k string) int {
	switch k {
	case "control_group":
		return 0
	case "chain":
		return 1
	case "operational":
		return 2
	}
	return 3
}

// buildControlGroups groups controls by (service, category) derived
// from the control ID prefix. CTL.S3.PUBLIC.001 -> service=s3,
// category=public. Each group becomes one capability listing the
// number of member controls and the asset types they apply to.
func buildControlGroups(controls []policy.ControlDefinition) []Capability {
	type groupKey struct {
		service, category string
	}
	groups := map[groupKey][]*policy.ControlDefinition{}
	for i := range controls {
		c := &controls[i]
		svc, cat := parseControlID(string(c.ID))
		if svc == "" {
			continue
		}
		k := groupKey{svc, cat}
		groups[k] = append(groups[k], c)
	}
	out := make([]Capability, 0, len(groups))
	for k, members := range groups {
		ids := make([]string, 0, len(members))
		assetTypes := map[string]struct{}{}
		var maxSev policy.Severity
		titleParts := map[string]struct{}{}
		var descs []string
		for _, m := range members {
			ids = append(ids, string(m.ID))
			for _, at := range m.ApplicableAssetTypes {
				assetTypes[string(at)] = struct{}{}
			}
			if m.Severity > maxSev {
				maxSev = m.Severity
			}
			if m.Name != "" {
				titleParts[m.Name] = struct{}{}
			}
			if m.Description != "" {
				descs = append(descs, m.Description)
			}
		}
		slices.Sort(ids)
		atList := make([]string, 0, len(assetTypes))
		for at := range assetTypes {
			atList = append(atList, at)
		}
		slices.Sort(atList)

		out = append(out, Capability{
			ID:          fmt.Sprintf("%s.%s", k.service, k.category),
			Kind:        "control_group",
			Title:       titleForGroup(k.service, k.category, len(members)),
			Description: summariseFirst(descs),
			Service:     k.service,
			Category:    k.category,
			AssetTypes:  atList,
			Severity:    maxSev.String(),
			ControlIDs:  ids,
			Keywords:    extractKeywordsFromControls(members),
			ExampleCmd:  "stave apply --controls controls --observations ./snapshots --max-unsafe 168h",
		})
	}
	return out
}

func buildChainCaps(chains []policy.ChainDefinition) []Capability {
	out := make([]Capability, 0, len(chains))
	for i := range chains {
		ch := &chains[i]
		out = append(out, Capability{
			ID:          "chain." + string(ch.ID),
			Kind:        "chain",
			Title:       humaniseID(string(ch.ID)),
			Description: summariseDescription(ch.Description),
			ChainIDs:    []string{string(ch.ID)},
			Keywords:    extractKeywordsFromText(ch.Description, string(ch.ID)),
			ExampleCmd:  "stave apply --controls controls --observations ./snapshots --max-unsafe 168h",
		})
	}
	return out
}

// operationalCaps is the hand-curated list of CLI features the
// proposal calls out: readiness, gaps, drift, duration, validate,
// proof export. These cross-cut the catalog and don't fit into the
// control-group/chain shape.
func operationalCaps() []Capability {
	return []Capability{
		{
			ID:          "ops.readiness",
			Kind:        "operational",
			Title:       "Check infrastructure readiness",
			Description: "Report what fraction of the catalog can fire against your snapshot's asset surface.",
			UseWhen:     "You want to know if your collector captured enough data for meaningful results.",
			ExampleCmd:  "stave readiness --observations ./snapshots/",
			Keywords:    []string{"readiness", "coverage", "missing", "completeness", "input", "what-can-fire"},
		},
		{
			ID:          "ops.gaps",
			Kind:        "operational",
			Title:       "Find missing observation properties",
			Description: "Field-level gap report. For each absent property, list controls and chains it would unlock if populated.",
			UseWhen:     "You want to know what to add to your observations for stronger detection.",
			ExampleCmd:  "stave gaps --observations ./snapshots/",
			Keywords:    []string{"gaps", "missing", "properties", "tags", "coverage", "unlock", "fields"},
		},
		{
			ID:          "ops.drift",
			Kind:        "operational",
			Title:       "Detect configuration changes between snapshots",
			Description: "Compare two snapshots and flag what changed with before-and-after state.",
			UseWhen:     "You want to know what changed since the last scan.",
			ExampleCmd:  "stave snapshot diff --before ./snapshot-march --after ./snapshot-april",
			Keywords:    []string{"drift", "change", "diff", "before", "after", "modification", "what-changed"},
		},
		{
			ID:          "ops.duration",
			Kind:        "operational",
			Title:       "Measure how long misconfigurations have persisted",
			Description: "Track unsafe duration across snapshots — the same finding at 6 hours vs 6 months tells different stories.",
			UseWhen:     "You need SLA urgency data or compliance exposure-duration evidence.",
			ExampleCmd:  "stave apply --observations ./snapshots/ --max-unsafe 168h --now <RFC3339>",
			Keywords:    []string{"duration", "time", "how-long", "sla", "persistence", "age", "exposure-window"},
		},
		{
			ID:          "ops.bisect",
			Kind:        "operational",
			Title:       "Find when a misconfiguration first appeared",
			Description: "Binary search across a snapshot archive to find the exact point a control became unsafe.",
			UseWhen:     "An auditor or incident asks 'how long has this been wrong?'",
			ExampleCmd:  "stave bisect --asset <arn> --history ./snapshots/",
			Keywords:    []string{"bisect", "when", "first-violation", "git-bisect", "history", "timeline"},
		},
		{
			ID:          "ops.forensics",
			Kind:        "operational",
			Title:       "Reconstruct one asset's full configuration timeline",
			Description: "Per-asset timeline across the snapshot archive — every property change, verdict transition, chain activation.",
			UseWhen:     "An auditor asks 'show me when this resource was non-compliant' or an incident timeline needs configuration state, not CloudTrail.",
			ExampleCmd:  "stave forensics --asset <arn> --history ./snapshots/",
			Keywords:    []string{"forensics", "timeline", "audit", "asset-history", "investigation"},
		},
		{
			ID:          "ops.validate",
			Kind:        "operational",
			Title:       "Validate observation files before evaluation",
			Description: "Schema check that a collector's output conforms to the obs.v0.1 contract before piping it into apply.",
			UseWhen:     "You built a custom collector and want to verify its output.",
			ExampleCmd:  "stave validate --in ./snapshot.json --kind observation --strict",
			Keywords:    []string{"validate", "schema", "contract", "format", "input", "obs.v0.1"},
		},
		{
			ID:          "ops.contract",
			Kind:        "operational",
			Title:       "Inspect the agent-facing contract for one asset type",
			Description: "Single-source view of the per-asset JSON Schema, the property paths the catalog reads, control + chain counts per path, and any Steampipe ingest mapping.",
			UseWhen:     "An agent or extractor needs to know how to populate observations for a given asset type.",
			ExampleCmd:  "stave contract show --asset-type aws_s3_bucket",
			Keywords:    []string{"contract", "schema", "agent", "ingest", "extractor", "steampipe", "asset-type"},
		},
		{
			ID:          "ops.proof",
			Kind:        "operational",
			Title:       "Export facts for mathematical safety proofs",
			Description: "Emit the snapshot's evaluation as JSONL triples or SMT-LIB v2 assertions for external reasoning engines (Z3, cvc5, Yices, Soufflé, Clingo, PySAT).",
			UseWhen:     "You want a solver to prove a dangerous state is unreachable, or enumerate every reachable violation atom.",
			ExampleCmd:  "stave export-sir --format smt2 --observations ./snapshots/ > facts.smt2",
			Keywords:    []string{"proof", "z3", "cvc5", "yices", "smt", "soufflé", "clingo", "pysat", "formal", "verification", "engine", "export"},
		},
		{
			ID:          "ops.budget",
			Kind:        "operational",
			Title:       "Compute SLA burn rate across a fleet",
			Description: "Fraction of the allowed unsafe-window across all assets that has been consumed in a budget period. Use as a deployment-freeze gate.",
			UseWhen:     "You need a single number to gate releases or report to a board.",
			ExampleCmd:  "stave budget --history ./evidence-archive/runs/ --period 30d --sla-profile soc2 --fail-on-burn-rate 80",
			Keywords:    []string{"budget", "burn-rate", "sla", "freeze", "gate", "board", "fleet"},
		},
	}
}

// parseControlID returns (service, category) from a CTL.<SVC>.<CAT>.<...> ID.
// Empty service signals "skip this control" (no recognisable prefix).
func parseControlID(id string) (string, string) {
	if !strings.HasPrefix(id, "CTL.") {
		return "", ""
	}
	rest := strings.TrimPrefix(id, "CTL.")
	segs := strings.SplitN(rest, ".", 4)
	if len(segs) < 2 {
		return "", ""
	}
	svc := strings.ToLower(segs[0])
	cat := ""
	if len(segs) >= 2 {
		cat = strings.ToLower(segs[1])
	}
	return svc, cat
}

func titleForGroup(service, category string, n int) string {
	return fmt.Sprintf("%s — %s controls (%d)", strings.ToUpper(service), humaniseCategory(category), n)
}

func humaniseCategory(c string) string {
	if c == "" {
		return "general"
	}
	// Replace underscores and capitalise per word
	parts := strings.Split(c, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

func humaniseID(id string) string {
	parts := strings.Split(id, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

func summariseFirst(descs []string) string {
	if len(descs) == 0 {
		return ""
	}
	slices.Sort(descs)
	return summariseDescription(descs[0])
}

func summariseDescription(d string) string {
	flat := strings.Join(strings.Fields(d), " ")
	if len(flat) > 200 {
		flat = flat[:197] + "…"
	}
	return flat
}

func extractKeywordsFromControls(ctls []*policy.ControlDefinition) []string {
	seen := map[string]struct{}{}
	for _, c := range ctls {
		addKeywords(seen, c.Name)
		addKeywords(seen, c.Description)
		if c.Remediation != nil {
			addKeywords(seen, c.Remediation.Description)
		}
		for _, at := range c.ApplicableAssetTypes {
			addKeywords(seen, string(at))
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func extractKeywordsFromText(parts ...string) []string {
	seen := map[string]struct{}{}
	for _, p := range parts {
		addKeywords(seen, p)
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// addKeywords tokenises text and adds every non-stopword to the set.
func addKeywords(seen map[string]struct{}, text string) {
	for _, tok := range tokenise(text) {
		if isStopWord(tok) {
			continue
		}
		seen[tok] = struct{}{}
		// Expand domain synonyms so the keyword set covers what
		// users actually type (open, internet, dangling, etc.).
		for _, syn := range SynonymsFor(tok) {
			seen[syn] = struct{}{}
		}
	}
}

func tokenise(s string) []string {
	s = strings.ToLower(s)
	var out []string
	cur := strings.Builder{}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			cur.WriteRune(r)
		default:
			if cur.Len() >= 3 {
				out = append(out, cur.String())
			}
			cur.Reset()
		}
	}
	if cur.Len() >= 3 {
		out = append(out, cur.String())
	}
	return out
}

var stopWords = map[string]struct{}{
	"the": {}, "and": {}, "for": {}, "with": {}, "from": {}, "this": {}, "that": {},
	"are": {}, "not": {}, "must": {}, "any": {}, "all": {}, "into": {}, "out": {},
	"per": {}, "via": {}, "use": {}, "used": {}, "uses": {}, "see": {},
	"can": {}, "may": {}, "but": {}, "has": {}, "have": {}, "had": {}, "its": {},
	"aws": {}, "ctl": {}, "src": {},
}

func isStopWord(s string) bool {
	_, ok := stopWords[s]
	return ok
}
