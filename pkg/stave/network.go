package stave

import (
	"context"
	"errors"
	"fmt"

	"github.com/sufield/stave/internal/core/network"
)

// NetworkEnumerateConfig configures SSH path enumeration.
type NetworkEnumerateConfig struct {
	SnapshotsDir string
	Port         int
}

// NetworkProveConfig configures bastion routing proof.
type NetworkProveConfig struct {
	SnapshotsDir string
	Property     string
	Port         int
}

// DefaultSSHPort is the default port for SSH reachability and safety properties.
const DefaultSSHPort = network.DefaultSSHPort

func normalizePort(port int) int {
	if port <= 0 {
		return DefaultSSHPort
	}
	return port
}

// Validate checks that required fields are present in the enumerate configuration.
func (cfg NetworkEnumerateConfig) Validate() error {
	if cfg.SnapshotsDir == "" {
		return errors.New("network enumerate: --observations is required")
	}
	return nil
}

// NormalizedPort returns cfg.Port, or DefaultSSHPort if non-positive.
func (cfg NetworkEnumerateConfig) NormalizedPort() int {
	return normalizePort(cfg.Port)
}

// Validate checks that required fields are present in the prove configuration.
func (cfg NetworkProveConfig) Validate() error {
	if cfg.SnapshotsDir == "" {
		return errors.New("network prove: --observations is required")
	}
	return nil
}

// NormalizedPort returns cfg.Port, or DefaultSSHPort if non-positive.
func (cfg NetworkProveConfig) NormalizedPort() int {
	return normalizePort(cfg.Port)
}

// NetworkEnumerate loads observations and enumerates all SSH paths to
// production hosts.
func NetworkEnumerate(ctx context.Context, cfg NetworkEnumerateConfig) (*network.EnumerateResult, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.Port = cfg.NormalizedPort()

	g, err := loadNetworkGraph(ctx, cfg.SnapshotsDir)
	if err != nil {
		return nil, fmt.Errorf("network enumerate: %w", err)
	}
	paths := g.EnumerateSSHPaths(cfg.Port)

	return network.NewEnumerateResult("production", cfg.Port, g.ProductionHostCount(), paths), nil
}

// NetworkProve loads observations and runs a network safety property proof.
func NetworkProve(ctx context.Context, cfg NetworkProveConfig) (*network.ProofResult, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.Port = cfg.NormalizedPort()

	g, err := loadNetworkGraph(ctx, cfg.SnapshotsDir)
	if err != nil {
		return nil, fmt.Errorf("network prove: %w", err)
	}

	r, err := g.Prove(cfg.Property, cfg.Port)
	if err != nil {
		return nil, fmt.Errorf("network prove: %w", err)
	}
	return r, nil
}

func loadNetworkGraph(ctx context.Context, dir string) (*network.Graph, error) {
	snapshots, err := loadSnapshots(ctx, dir)
	if err != nil {
		return nil, err
	}
	return network.BuildGraph(snapshots), nil
}
