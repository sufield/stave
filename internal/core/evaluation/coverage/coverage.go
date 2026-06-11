// Package coverage aggregates per-control alternative-tool annotations
// into per-tool / per-domain coverage posture.
//
// This package is tool-agnostic by construction: it never pattern-matches
// on tool names. Tool identifiers are opaque strings carried through from
// control YAML alternatives blocks and inventory files.
package coverage

import (
	"sort"

	"github.com/sufield/stave/internal/core/controldef"
)

// Alternative is the canonical per-finding annotation used by output
// adapters. It mirrors controldef.Alternative without exposing the
// CoverageStatus type to keep the wire format simple.
type Alternative struct {
	Tool     string
	CheckID  string
	Coverage string
	Note     string
}

// DomainCoverage is the per-(tool, domain) summary surfaced in apply
// output. Total and NotCoveredChecks are zero/nil when no inventory was
// loaded for the corresponding tool.
type DomainCoverage struct {
	Covered          int
	Total            int
	NotCoveredChecks []string
}

// CoverageIndex is the per-tool, per-domain aggregation produced by
// BuildCoverageIndex. The outer key is the tool identifier; the inner
// key is the domain identifier resolved from the inventory.
type CoverageIndex struct {
	ByTool map[string]map[string]DomainCoverage
}

// ToolNames returns the sorted list of tools represented in the
// coverage data. Domain question: what tools does this assessment's
// coverage posture cover?
func (c CoverageIndex) ToolNames() []string {
	names := make([]string, 0, len(c.ByTool))
	for tool := range c.ByTool {
		names = append(names, tool)
	}
	sort.Strings(names)
	return names
}

// DomainsForTool returns the sorted list of domains the named tool
// covers. Returns an empty (non-nil) slice when the tool is not
// represented in the coverage data. Domain question: what domains
// does this tool cover in this assessment?
func (c CoverageIndex) DomainsForTool(tool string) []string {
	domains, ok := c.ByTool[tool]
	if !ok {
		return []string{}
	}
	names := make([]string, 0, len(domains))
	for d := range domains {
		names = append(names, d)
	}
	sort.Strings(names)
	return names
}

// ToolInventory enumerates the canonical check identifiers a single
// alternative tool publishes for a single domain. Stave loads
// inventories from data/alternatives/*.yaml at runtime; the file shape
// declares (tool, domain) once and a flat list of check IDs.
type ToolInventory struct {
	Tool   string
	Domain string
	Checks []string
}

// unmatchedDomain is the bucket used when a control's alternative entry
// references a (tool, check_id) pair the inventory does not know about.
// Surfacing it preserves the annotation in output without polluting the
// real domain buckets.
const unmatchedDomain = "_unmatched"

// BuildCoverageIndex aggregates per-control alternatives annotations
// into per-tool / per-domain coverage counts.
//
// inventories is optional: when nil or empty for a given tool, that
// tool's DomainCoverage entries carry Total=0 and NotCoveredChecks=nil
// (only declared coverage is visible). When inventories are provided,
// each alternative's (tool, check_id) is resolved to the domain
// declared by the matching inventory file, and uncovered checks are
// computed by set difference.
func BuildCoverageIndex(controls []controldef.ControlDefinition, inventories []ToolInventory) CoverageIndex {
	checkDomain := buildInventoryIndex(inventories)
	covered := collectCovered(controls, checkDomain)
	return assemble(covered, inventories)
}

// buildInventoryIndex returns a (tool, check_id) -> domain map built
// from the provided inventory list. Duplicate (tool, check_id) entries
// across different inventory files keep the first domain seen.
func buildInventoryIndex(inventories []ToolInventory) map[checkKey]string {
	idx := make(map[checkKey]string)
	for _, inv := range inventories {
		for _, id := range inv.Checks {
			k := checkKey{tool: inv.Tool, checkID: id}
			if _, exists := idx[k]; exists {
				continue
			}
			idx[k] = inv.Domain
		}
	}
	return idx
}

// collectCovered walks every control's alternatives block and groups
// covered check IDs by (tool, domain). The set is keyed on tool +
// check_id so a single check_id covered by N controls counts once.
func collectCovered(controls []controldef.ControlDefinition, checkDomain map[checkKey]string) map[toolDomain]map[string]struct{} {
	out := make(map[toolDomain]map[string]struct{})
	for i := range controls {
		for _, alt := range controls[i].Alternatives {
			domain, ok := checkDomain[checkKey{tool: alt.Tool, checkID: alt.CheckID}]
			if !ok {
				domain = unmatchedDomain
			}
			td := toolDomain{tool: alt.Tool, domain: domain}
			set, exists := out[td]
			if !exists {
				set = make(map[string]struct{})
				out[td] = set
			}
			set[alt.CheckID] = struct{}{}
		}
	}
	return out
}

// assemble materializes the CoverageIndex from collected coverage and
// the inventory totals. Tools with an inventory but no annotations
// still appear in the index so apply output communicates "0 of N
// covered" rather than silently hiding the tool.
func assemble(covered map[toolDomain]map[string]struct{}, inventories []ToolInventory) CoverageIndex {
	idx := CoverageIndex{ByTool: make(map[string]map[string]DomainCoverage)}

	for td, ids := range covered {
		dc := lookup(idx, td.tool, td.domain)
		dc.Covered = len(ids)
		store(idx, td.tool, td.domain, dc)
	}

	for _, inv := range inventories {
		dc := lookup(idx, inv.Tool, inv.Domain)
		uniqueChecks := make([]string, 0, len(inv.Checks))
		seen := make(map[string]struct{})
		for _, id := range inv.Checks {
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				uniqueChecks = append(uniqueChecks, id)
			}
		}
		dc.Total = len(uniqueChecks)
		dc.NotCoveredChecks = missingChecks(uniqueChecks, covered[toolDomain{tool: inv.Tool, domain: inv.Domain}])
		store(idx, inv.Tool, inv.Domain, dc)
	}

	return idx
}

func lookup(idx CoverageIndex, tool, domain string) DomainCoverage {
	if domains, ok := idx.ByTool[tool]; ok {
		return domains[domain]
	}
	return DomainCoverage{}
}

func store(idx CoverageIndex, tool, domain string, dc DomainCoverage) {
	domains, ok := idx.ByTool[tool]
	if !ok {
		domains = make(map[string]DomainCoverage)
		idx.ByTool[tool] = domains
	}
	domains[domain] = dc
}

// missingChecks returns the inventory entries that no control covers,
// sorted lexicographically for stable output.
func missingChecks(inventoryChecks []string, coveredSet map[string]struct{}) []string {
	if len(inventoryChecks) == 0 {
		return nil
	}
	missing := make([]string, 0)
	for _, id := range inventoryChecks {
		if _, ok := coveredSet[id]; !ok {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) == 0 {
		return nil
	}
	return missing
}

type checkKey struct {
	tool    string
	checkID string
}

type toolDomain struct {
	tool   string
	domain string
}
