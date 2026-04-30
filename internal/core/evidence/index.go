package evidence

import (
	"fmt"
	"slices"
	"strings"
	"sync"
)

// CitationEntry is a control that addresses a specific regulatory requirement.
type CitationEntry struct {
	ControlID   string
	ControlName string
	Severity    string
	Domain      string
	AttackStage string
}

// CitationIndex maps framework requirements to the controls that address them.
// All methods are safe for concurrent use — callers may build the index from
// multiple goroutines and read while building.
type CitationIndex struct {
	mu      sync.RWMutex
	entries map[string][]CitationEntry
}

// NewCitationIndex creates an empty citation index.
func NewCitationIndex() *CitationIndex {
	return &CitationIndex{
		entries: make(map[string][]CitationEntry),
	}
}

// Add registers a control as addressing a specific framework requirement.
func (idx *CitationIndex) Add(framework, requirement string, entry CitationEntry) {
	key := citationKey(framework, requirement)
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.entries[key] = append(idx.entries[key], entry)
}

// Lookup returns all controls addressing a specific framework requirement.
// The returned slice is a clone — callers may mutate it freely.
func (idx *CitationIndex) Lookup(framework, requirement string) []CitationEntry {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return slices.Clone(idx.entries[citationKey(framework, requirement)])
}

// CitationCoverage reports how many requirements in a framework have at
// least one Stave control addressing them.
type CitationCoverage struct {
	Framework             string   `json:"framework"`
	TotalRequirements     int      `json:"total_requirements"`
	CoveredRequirements   int      `json:"covered_requirements"`
	UncoveredRequirements []string `json:"uncovered_requirements,omitempty"`
	CoveragePercent       float64  `json:"coverage_percent"`
}

// Coverage computes what percentage of a framework's requirements have
// at least one Stave control. totalRequirements is the total count of
// requirements in the framework catalog.
func (idx *CitationIndex) Coverage(framework string, totalRequirements int) CitationCoverage {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	prefix := framework + ":"
	covered := make(map[string]bool)
	for key := range idx.entries {
		if after, ok := strings.CutPrefix(key, prefix); ok {
			req := after
			covered[req] = true
		}
	}

	cov := CitationCoverage{
		Framework:           framework,
		TotalRequirements:   totalRequirements,
		CoveredRequirements: len(covered),
	}
	if totalRequirements > 0 {
		cov.CoveragePercent = float64(len(covered)) / float64(totalRequirements) * 100
	}
	return cov
}

// Frameworks returns all framework names present in the index.
func (idx *CitationIndex) Frameworks() []string {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	seen := make(map[string]bool)
	for key := range idx.entries {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) == 2 {
			seen[parts[0]] = true
		}
	}
	var out []string
	for f := range seen {
		out = append(out, f)
	}
	slices.Sort(out)
	return out
}

// RequirementsFor returns all requirement IDs covered for a framework.
func (idx *CitationIndex) RequirementsFor(framework string) []string {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	prefix := framework + ":"
	var reqs []string
	for key := range idx.entries {
		if after, ok := strings.CutPrefix(key, prefix); ok {
			reqs = append(reqs, after)
		}
	}
	slices.Sort(reqs)
	return reqs
}

// Size returns the total number of citation entries in the index.
func (idx *CitationIndex) Size() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	total := 0
	for _, entries := range idx.entries {
		total += len(entries)
	}
	return total
}

func citationKey(framework, requirement string) string {
	return fmt.Sprintf("%s:%s", strings.TrimSpace(framework), strings.TrimSpace(requirement))
}
