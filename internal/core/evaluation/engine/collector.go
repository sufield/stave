package engine

import (
	"sync"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// assetRegistry provides an internal set for tracking unique cloud assets.
type assetRegistry map[asset.ID]struct{}

// register inserts an asset ID and returns true if it is a new discovery.
func (s assetRegistry) register(id asset.ID) bool {
	if _, ok := s[id]; ok {
		return false
	}
	s[id] = struct{}{}
	return true
}

// AssessmentCollector gathers security findings, resource checks, and
// compliance metadata across multiple evaluation cycles.
// All methods are safe for concurrent use.
type AssessmentCollector struct {
	mu              sync.Mutex
	findings        []evaluation.Finding
	checks          []evaluation.ResourceCheck
	skippedControls []evaluation.SkippedControl
	exemptedAssets  []asset.ExemptedAsset

	seenAssets         assetRegistry
	nonCompliantAssets assetRegistry
	exemptAssets       assetRegistry
}

// NewCollector initializes the assessment collector.
// assetHint allows for pre-allocation of tracking registries based on observation size.
func NewCollector(assetHint int) *AssessmentCollector {
	return &AssessmentCollector{
		seenAssets:         make(assetRegistry, assetHint),
		nonCompliantAssets: make(assetRegistry, assetHint),
		exemptAssets:       make(assetRegistry, assetHint),
	}
}

// RecordExemption marks an asset as exempt from policy enforcement.
// It returns true if this is the first time the asset has been exempted in the session.
func (c *AssessmentCollector) RecordExemption(id asset.ID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exemptAssets.register(id)
}

// RecordSkippedControl logs a security control that was bypassed during the run.
func (c *AssessmentCollector) RecordSkippedControl(id kernel.ControlID, name, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.skippedControls = append(c.skippedControls, evaluation.SkippedControl{
		ControlID:   id,
		ControlName: name,
		Reason:      reason,
	})
}

// RecordExemptedAsset appends the detail of an exempted asset to the final report.
func (c *AssessmentCollector) RecordExemptedAsset(id asset.ID, pattern, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.exemptedAssets = append(c.exemptedAssets, asset.ExemptedAsset{
		ID:      id,
		Pattern: pattern,
		Reason:  reason,
	})
}

// RecordCheck appends a granular resource evaluation result.
func (c *AssessmentCollector) RecordCheck(check evaluation.ResourceCheck) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks = append(c.checks, check)
}

// RecordFindings appends a batch of identified security violations.
func (c *AssessmentCollector) RecordFindings(findings []*evaluation.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range findings {
		if f != nil {
			c.findings = append(c.findings, *f)
		}
	}
}
