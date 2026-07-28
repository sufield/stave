//go:build ignore

package main

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type chainDef struct {
	ID             string   `yaml:"id"`
	Controls       []string `yaml:"controls"`
	Preconditions  []string `yaml:"preconditions"`
	Postconditions []string `yaml:"postconditions"`
}

func loadChains(dir string) ([]chainDef, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var chains []chainDef
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var c chainDef
		if yaml.Unmarshal(data, &c) == nil && c.ID != "" {
			chains = append(chains, c)
		}
	}
	return chains, nil
}

// dedup classifies discovered paths as novel or confirmed.
//
// A discovered path is "confirmed" if any known chain's
// preconditions/postconditions match the path's category:
//
//	escalation → postcondition contains privilege_escalation/admin_access/shadow_admin_access
//	exfiltration → postcondition contains data_access/data_exfiltration
//	external-reach → precondition contains cross_account_access
//	confused-deputy → precondition contains confused_deputy
//
// This is a coarse match — it answers "does any known chain
// cover this risk class?" not "does a known chain cover this
// exact path." Exact-path matching requires the chain YAML
// to enumerate specific ARNs, which they don't — chains are
// patterns, not instances.
func dedup(paths []discoveredPath, chains []chainDef) (novel, confirmed []discoveredPath) {
	escalationPostconds := map[string]bool{
		"privilege_escalation": true,
		"admin_access":         true,
		"shadow_admin_access":  true,
		"full_account_admin":   true,
	}
	exfilPostconds := map[string]bool{
		"data_access":        true,
		"data_exfiltration":  true,
		"training_data_leak": true,
	}
	crossAccountPreconds := map[string]bool{
		"cross_account_access": true,
		"external_access":      true,
	}
	confusedDeputyPreconds := map[string]bool{
		"confused_deputy": true,
	}

	hasMatch := func(category string) bool {
		for _, c := range chains {
			switch category {
			case "escalation":
				for _, pc := range c.Postconditions {
					if escalationPostconds[pc] {
						return true
					}
				}
			case "exfiltration":
				for _, pc := range c.Postconditions {
					if exfilPostconds[pc] {
						return true
					}
				}
			case "external-reach":
				for _, pc := range c.Preconditions {
					if crossAccountPreconds[pc] {
						return true
					}
				}
			case "confused-deputy":
				for _, pc := range c.Preconditions {
					if confusedDeputyPreconds[pc] {
						return true
					}
				}
			}
		}
		return false
	}

	// Pre-compute which categories have known chain coverage.
	covered := map[string]bool{}
	for _, cat := range []string{"escalation", "exfiltration", "external-reach", "confused-deputy"} {
		covered[cat] = hasMatch(cat)
	}

	for _, p := range paths {
		if covered[p.Category] {
			confirmed = append(confirmed, p)
		} else {
			novel = append(novel, p)
		}
	}
	return
}
