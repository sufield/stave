package stave

import (
	"fmt"
	"slices"
	"strings"

	"encoding/json"

	"github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/core/capabilities"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// ServiceConnectivity describes a service's position in the control/chain graph.
type ServiceConnectivity struct {
	Service     string   `json:"service"`
	Controls    int      `json:"controls"`
	Chains      int      `json:"chains"`
	ConnectedTo []string `json:"connected_to"`
	Question    string   `json:"question,omitempty"`
}

// SiloReport is the output of structural silence detection.
type SiloReport struct {
	Silos         []ServiceConnectivity `json:"silos"`
	MostConnected []ServiceConnectivity `json:"most_connected"`
	Distribution  map[string]int        `json:"connectivity_distribution"`
	SiloCount     int                   `json:"silo_count"`
	TotalServices int                   `json:"total_services"`
	TotalControls int                   `json:"total_controls"`
	TotalChains   int                   `json:"total_chains"`
}

// SiloConfig parameterizes [GraphSilos].
type SiloConfig struct {
	ChainsDir   string
	MinControls int
}

// GraphSilos analyzes the control/chain graph to find services with
// controls but zero compound chains connecting them to other services.
func GraphSilos(cfg SiloConfig) (*SiloReport, error) {
	controls, err := builtinControls()
	if err != nil {
		return nil, err
	}

	chainsDir := cfg.ChainsDir
	if chainsDir == "" {
		chainsDir = "chains"
	}
	chains, err := yaml.LoadChains(chainsDir, capabilities.Builtin())
	if err != nil {
		return nil, fmt.Errorf("load chains: %w", err)
	}

	return buildSiloReport(controls, chains, cfg.MinControls), nil
}

// GraphSilosJSON returns the silo report as indented JSON.
func GraphSilosJSON(cfg SiloConfig) ([]byte, error) {
	report, err := GraphSilos(cfg)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(report, "", "  ")
}

func buildSiloReport(controls []policy.ControlDefinition, chains []policy.ChainDefinition, minControls int) *SiloReport {
	if minControls < 1 {
		minControls = 1
	}

	serviceControls := indexControlsByService(controls)
	serviceChains, serviceConnections := indexChainConnectivity(chains)

	var silos, connected []ServiceConnectivity
	for svc, count := range serviceControls {
		sc := ServiceConnectivity{
			Service:     svc,
			Controls:    count,
			Chains:      serviceChains[svc],
			ConnectedTo: serviceConnections[svc],
		}
		slices.Sort(sc.ConnectedTo)
		if sc.Chains == 0 && sc.Controls >= minControls {
			sc.Question = structuralQuestion(svc, count)
			silos = append(silos, sc)
		} else if sc.Chains > 0 {
			connected = append(connected, sc)
		}
	}

	slices.SortFunc(silos, func(a, b ServiceConnectivity) int {
		if a.Controls != b.Controls {
			return b.Controls - a.Controls
		}
		return strings.Compare(a.Service, b.Service)
	})
	slices.SortFunc(connected, func(a, b ServiceConnectivity) int {
		if a.Chains != b.Chains {
			return b.Chains - a.Chains
		}
		return strings.Compare(a.Service, b.Service)
	})

	top := connected
	if len(top) > 10 {
		top = top[:10]
	}

	dist := map[string]int{"0_chains": 0, "1-5_chains": 0, "6-20_chains": 0, "21+_chains": 0}
	for svc := range serviceControls {
		c := serviceChains[svc]
		switch {
		case c == 0:
			dist["0_chains"]++
		case c <= 5:
			dist["1-5_chains"]++
		case c <= 20:
			dist["6-20_chains"]++
		default:
			dist["21+_chains"]++
		}
	}

	return &SiloReport{
		Silos:         silos,
		MostConnected: top,
		Distribution:  dist,
		SiloCount:     len(silos),
		TotalServices: len(serviceControls),
		TotalControls: len(controls),
		TotalChains:   len(chains),
	}
}

// indexControlsByService maps lowercase service name → control count.
func indexControlsByService(controls []policy.ControlDefinition) map[string]int {
	m := make(map[string]int)
	for i := range controls {
		svc := strings.ToLower(controls[i].ID.Provider())
		if svc != "" {
			m[svc]++
		}
	}
	return m
}

// indexChainConnectivity returns per-service chain counts and connections.
func indexChainConnectivity(chains []policy.ChainDefinition) (chainCount map[string]int, connections map[string][]string) {
	chainCount = make(map[string]int)
	connSet := make(map[string]map[string]bool)

	for i := range chains {
		services := chainServices(chains[i].ControlIDs)
		for svc := range services {
			chainCount[svc]++
		}
		if len(services) > 1 {
			svcs := make([]string, 0, len(services))
			for s := range services {
				svcs = append(svcs, s)
			}
			for _, a := range svcs {
				for _, b := range svcs {
					if a != b {
						if connSet[a] == nil {
							connSet[a] = make(map[string]bool)
						}
						connSet[a][b] = true
					}
				}
			}
		}
	}

	connections = make(map[string][]string)
	for svc, peers := range connSet {
		for p := range peers {
			connections[svc] = append(connections[svc], p)
		}
	}
	return chainCount, connections
}

func chainServices(ids []kernel.ControlID) map[string]bool {
	m := make(map[string]bool)
	for _, id := range ids {
		svc := strings.ToLower(id.Provider())
		if svc != "" {
			m[svc] = true
		}
	}
	return m
}

func structuralQuestion(service string, controlCount int) string {
	return fmt.Sprintf(
		"%s has %d controls but participates in zero compound chains. "+
			"What cross-service failure involves %s + IAM/VPC/KMS?",
		service, controlCount, service)
}
