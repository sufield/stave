package main

import "context"

// GapEngine is the interface every discovery engine implements.
type GapEngine interface {
	Name() string
	Run(ctx context.Context) (*EngineResult, error)
}

func allEngines() []GapEngine {
	return []GapEngine{
		&botocoreEngine{},
		&terraformEngine{},
		&deprecationEngine{},
		&semanticDiffEngine{},
	}
}

func filterEngines(engines []GapEngine, names []string) []GapEngine {
	if len(names) == 0 {
		return engines
	}
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	var out []GapEngine
	for _, e := range engines {
		if set[e.Name()] {
			out = append(out, e)
		}
	}
	return out
}
