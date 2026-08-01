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

// NetworkEnumerate loads observations and enumerates all SSH paths to
// production hosts.
func NetworkEnumerate(ctx context.Context, cfg NetworkEnumerateConfig) (*network.EnumerateResult, error) {
	if cfg.SnapshotsDir == "" {
		return nil, errors.New("network enumerate: --observations is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}

	snapshots, err := loadSnapshots(ctx, cfg.SnapshotsDir)
	if err != nil {
		return nil, fmt.Errorf("network enumerate: %w", err)
	}

	g := network.BuildGraph(snapshots)
	paths := g.EnumerateSSHPaths(cfg.Port)

	return &network.EnumerateResult{
		Scope:           "production",
		Port:            cfg.Port,
		ProductionHosts: len(g.ProductionHosts()),
		Paths:           paths,
	}, nil
}

// NetworkProve loads observations and runs a network safety property proof.
func NetworkProve(ctx context.Context, cfg NetworkProveConfig) (*network.ProofResult, error) {
	if cfg.SnapshotsDir == "" {
		return nil, errors.New("network prove: --observations is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}

	snapshots, err := loadSnapshots(ctx, cfg.SnapshotsDir)
	if err != nil {
		return nil, fmt.Errorf("network prove: %w", err)
	}

	g := network.BuildGraph(snapshots)

	switch cfg.Property {
	case "bastion-ssh", "":
		r, err := g.ProveBastionSSH(cfg.Port)
		if err != nil {
			return nil, fmt.Errorf("network prove: %w", err)
		}
		return r, nil
	default:
		return nil, fmt.Errorf("network prove: unknown property %q (valid: bastion-ssh)", cfg.Property)
	}
}
