package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type deprecationEngine struct{}

func (e *deprecationEngine) Name() string { return "deprecation" }

func (e *deprecationEngine) Run(ctx context.Context) (*EngineResult, error) {
	start := time.Now()

	calendarPath := "data/deprecation-calendar.yaml"
	data, err := os.ReadFile(calendarPath)
	if err != nil {
		return &EngineResult{
			Engine:   "deprecation",
			Duration: time.Since(start),
			Error:    fmt.Sprintf("calendar not found at %s", calendarPath),
		}, nil
	}

	var cal deprecationCalendar
	if err := yaml.Unmarshal(data, &cal); err != nil {
		return &EngineResult{
			Engine:   "deprecation",
			Duration: time.Since(start),
			Error:    fmt.Sprintf("parse calendar: %v", err),
		}, nil
	}

	catalog := loadCatalog()
	controlIDs := make(map[string]bool)
	for _, ctl := range catalog.List() {
		controlIDs[string(ctl.ID)] = true
	}

	var gaps []Gap
	var total int

	for _, eng := range cal.Engines {
		for _, ver := range eng.DeprecatedVersions {
			total++
			ctlID := fmt.Sprintf("CTL.%s.%s.EOL.001",
				upper(eng.Service), upper(eng.Engine))
			if controlIDs[ctlID] {
				continue
			}
			gaps = append(gaps, Gap{
				Service:     eng.Service,
				Property:    fmt.Sprintf("%s version %s (EOL %s)", eng.Engine, ver, eng.EOLDate),
				Description: fmt.Sprintf("%s %s version %s is past end-of-life", eng.Service, eng.Engine, ver),
				Severity:    "High",
				Taxonomy:    []string{"deprecation"},
				Source:      "deprecation",
				Confidence:  "High",
			})
		}
	}

	for _, pol := range cal.TLSPolicies {
		for _, dp := range pol.DeprecatedPolicies {
			total++
			gaps = append(gaps, Gap{
				Service:     pol.Service,
				Property:    fmt.Sprintf("TLS policy %s", dp),
				Description: fmt.Sprintf("%s TLS policy %s is deprecated", pol.Service, dp),
				Severity:    "High",
				Taxonomy:    []string{"encryption-in-transit", "deprecation"},
				Source:      "deprecation",
				Confidence:  "High",
			})
		}
	}

	for _, s := range cal.Superseded {
		total++
		gaps = append(gaps, Gap{
			Service:     s.Artifact,
			Property:    fmt.Sprintf("superseded by %s (since %s)", s.Replacement, s.DeprecatedDate),
			Description: fmt.Sprintf("%s is superseded by %s", s.Artifact, s.Replacement),
			Severity:    "Medium",
			Taxonomy:    []string{"deprecation"},
			Source:      "deprecation",
			Confidence:  "High",
		})
	}

	return &EngineResult{
		Engine:       "deprecation",
		GapsFound:    gaps,
		Covered:      total - len(gaps),
		TotalChecked: total,
		Duration:     time.Since(start),
		DataSource:   calendarPath,
	}, nil
}

type deprecationCalendar struct {
	Engines    []engineEntry    `yaml:"engines"`
	TLSPolicies []tlsPolicyEntry `yaml:"tls_policies"`
	Superseded []supersededEntry `yaml:"superseded"`
}

type engineEntry struct {
	Service            string   `yaml:"service"`
	Engine             string   `yaml:"engine"`
	DeprecatedVersions []string `yaml:"deprecated_versions"`
	EOLDate            string   `yaml:"eol_date"`
}

type tlsPolicyEntry struct {
	Service            string   `yaml:"service"`
	DeprecatedPolicies []string `yaml:"deprecated_policies"`
}

type supersededEntry struct {
	Artifact       string `yaml:"artifact"`
	Replacement    string `yaml:"replacement"`
	DeprecatedDate string `yaml:"deprecated_date"`
}

func upper(s string) string {
	result := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		result[i] = c
	}
	return string(result)
}
