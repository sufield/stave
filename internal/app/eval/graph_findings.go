package eval

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// graphChainSpec maps a Soufflé output relation to finding metadata.
type graphChainSpec struct {
	ChainID     kernel.ChainID
	Description string
	Severity    policy.Severity
	Columns     int
	Stages      []kernel.AttackStage
	Narrative   func(cols []string) string
	Resource    func(cols []string) asset.ID
}

// graphChainRegistry maps Soufflé relation names to their chain specs.
// Each entry corresponds to a .csv file in the Soufflé output directory.
var graphChainRegistry = map[string]graphChainSpec{
	"bucket_hijack_path": {
		ChainID:     "CHAIN.BUCKET.HIJACK.001",
		Description: "S3 bucket hijack via DeleteBucket on a stream destination without SCP data perimeter",
		Severity:    policy.SeverityCritical,
		Columns:     4,
		Stages:      []kernel.AttackStage{"initial_access", "persistence", "impact"},
		Narrative: func(cols []string) string {
			return fmt.Sprintf("Identity %q has s3:DeleteBucket on %q which is the destination for %s %q. No SCP data perimeter blocks cross-account writes.",
				col(cols, 0), col(cols, 1), col(cols, 3), col(cols, 2))
		},
		Resource: func(cols []string) asset.ID { return asset.ID(col(cols, 1)) },
	},
	"telemetry_hijack_path": {
		ChainID:     "CHAIN.BUCKET.TELEMETRY_HIJACK.001",
		Description: "Security telemetry bucket deletion blinds the monitoring pipeline",
		Severity:    policy.SeverityCritical,
		Columns:     4,
		Stages:      []kernel.AttackStage{"initial_access", "detection_evasion", "impact"},
		Narrative: func(cols []string) string {
			return fmt.Sprintf("Identity %q has s3:DeleteBucket on security telemetry bucket %q (destination for %s %q). Bucket deletion blinds the telemetry pipeline.",
				col(cols, 0), col(cols, 1), col(cols, 3), col(cols, 2))
		},
		Resource: func(cols []string) asset.ID { return asset.ID(col(cols, 1)) },
	},
	"cross_account_data_destruction": {
		ChainID:     "CHAIN.BUCKET.CROSS_ACCOUNT_DESTROY.001",
		Description: "Cross-account data destruction via external principal with destructive access to stream destination",
		Severity:    policy.SeverityCritical,
		Columns:     5,
		Stages:      []kernel.AttackStage{"initial_access", "impact"},
		Narrative: func(cols []string) string {
			return fmt.Sprintf("External principal %q has %s on stream destination %q (router %s %q). No SCP data perimeter blocks the grant.",
				col(cols, 0), col(cols, 4), col(cols, 1), col(cols, 3), col(cols, 2))
		},
		Resource: func(cols []string) asset.ID { return asset.ID(col(cols, 1)) },
	},
	"cross_account_policy_rewrite": {
		ChainID:     "CHAIN.BUCKET.CROSS_ACCOUNT_REWRITE.001",
		Description: "Cross-account bucket policy rewrite enables arbitrary further access",
		Severity:    policy.SeverityHigh,
		Columns:     3,
		Stages:      []kernel.AttackStage{"privilege_escalation"},
		Narrative: func(cols []string) string {
			return fmt.Sprintf("External principal %q can rewrite the bucket policy on %q (grant type: %s), enabling arbitrary further access.",
				col(cols, 0), col(cols, 1), col(cols, 2))
		},
		Resource: func(cols []string) asset.ID { return asset.ID(col(cols, 1)) },
	},
	"permission_asymmetry": {
		ChainID:     "CHAIN.BUCKET.PERMISSION_ASYMMETRY.001",
		Description: "Delete permission on stream destination bypasses intended permission boundary",
		Severity:    policy.SeverityHigh,
		Columns:     5,
		Stages:      []kernel.AttackStage{"initial_access", "impact"},
		Narrative: func(cols []string) string {
			return fmt.Sprintf("Identity %q can delete stream destination %q but lacks %s on %s %q. Bucket deletion bypasses the intended permission boundary.",
				col(cols, 0), col(cols, 1), col(cols, 4), col(cols, 3), col(cols, 2))
		},
		Resource: func(cols []string) asset.ID { return asset.ID(col(cols, 1)) },
	},
	"dangling_destination": {
		ChainID:     "CHAIN.BUCKET.DANGLING_DEST.001",
		Description: "Router references non-existent bucket — attacker could create it to capture data",
		Severity:    policy.SeverityHigh,
		Columns:     3,
		Stages:      []kernel.AttackStage{"initial_access"},
		Narrative: func(cols []string) string {
			return fmt.Sprintf("Router %q (%s) references bucket %q which does not exist in the snapshot. An attacker could create this bucket to capture the data stream.",
				col(cols, 0), col(cols, 2), col(cols, 1))
		},
		Resource: func(cols []string) asset.ID { return asset.ID(col(cols, 0)) },
	},
	"cross_account_destination": {
		ChainID:     "CHAIN.BUCKET.CROSS_ACCOUNT_DEST.001",
		Description: "Data routed to bucket in a different account without explicit authorization",
		Severity:    policy.SeverityMedium,
		Columns:     5,
		Stages:      []kernel.AttackStage{kernel.AttackStageCollection},
		Narrative: func(cols []string) string {
			return fmt.Sprintf("Router %q (%s) sends data to bucket %q in account %s, different from source account %s.",
				col(cols, 0), col(cols, 2), col(cols, 1), col(cols, 4), col(cols, 3))
		},
		Resource: func(cols []string) asset.ID { return asset.ID(col(cols, 1)) },
	},
	"lateral_via_resource_policy": {
		ChainID:     "CHAIN.LATERAL.RESOURCE_POLICY.001",
		Description: "Lateral movement via role trust chain into resource policy grant",
		Severity:    policy.SeverityHigh,
		Columns:     5,
		Stages:      []kernel.AttackStage{kernel.AttackStageLateralMovement, kernel.AttackStageCollection},
		Narrative: func(cols []string) string {
			return fmt.Sprintf("Identity %q assumes role %q, which has resource-policy grant (%s, type %s) to %q. Cross-type lateral movement: role trust chain into resource policy grant.",
				col(cols, 0), col(cols, 1), col(cols, 3), col(cols, 4), col(cols, 2))
		},
		Resource: func(cols []string) asset.ID { return asset.ID(col(cols, 2)) },
	},
	"assume_cycle": {
		ChainID:     "CHAIN.TRUST.CYCLE.001",
		Description: "Role assumption cycle enables privilege laundering",
		Severity:    policy.SeverityHigh,
		Columns:     3,
		Stages:      []kernel.AttackStage{"privilege_escalation", "lateral_movement"},
		Narrative: func(cols []string) string {
			return fmt.Sprintf("Trust cycle detected: %q ↔ %q (%s hops). A cycle in the role assumption graph enables privilege laundering — assume out, then assume back with different permissions.",
				col(cols, 0), col(cols, 1), col(cols, 2))
		},
		Resource: func(cols []string) asset.ID { return asset.ID(col(cols, 0)) },
	},
	"unauthorized_access": {
		ChainID:     "CHAIN.IAM.UNAUTHORIZED_ACCESS.001",
		Description: "Effective access to sensitive resource without authorization",
		Severity:    policy.SeverityHigh,
		Columns:     3,
		Stages:      []kernel.AttackStage{kernel.AttackStageCollection},
		Narrative: func(cols []string) string {
			return fmt.Sprintf("Principal %q has effective access to %q via action %q without authorization.",
				col(cols, 0), col(cols, 1), col(cols, 2))
		},
		Resource: func(cols []string) asset.ID { return asset.ID(col(cols, 1)) },
	},
	"violation_c": {
		ChainID:     "CHAIN.CIA.CONFIDENTIALITY.001",
		Description: "Unauthorized read access to high-sensitivity resource",
		Severity:    policy.SeverityCritical,
		Columns:     3,
		Stages:      []kernel.AttackStage{kernel.AttackStageCollection, "exfiltration"},
		Narrative: func(cols []string) string {
			return fmt.Sprintf("Principal %q has unauthorized read action %q on high-sensitivity resource %q — confidentiality violation.",
				col(cols, 0), col(cols, 2), col(cols, 1))
		},
		Resource: func(cols []string) asset.ID { return asset.ID(col(cols, 1)) },
	},
	"violation_i": {
		ChainID:     "CHAIN.CIA.INTEGRITY.001",
		Description: "Unauthorized write access to high-sensitivity resource",
		Severity:    policy.SeverityCritical,
		Columns:     3,
		Stages:      []kernel.AttackStage{"impact"},
		Narrative: func(cols []string) string {
			return fmt.Sprintf("Principal %q has unauthorized write action %q on high-sensitivity resource %q — integrity violation.",
				col(cols, 0), col(cols, 2), col(cols, 1))
		},
		Resource: func(cols []string) asset.ID { return asset.ID(col(cols, 1)) },
	},
}

// ingestGraphFindings reads Soufflé output from dir and converts each
// tuple to a CompoundFinding using the graph chain registry.
// Returns nil findings (not error) if dir does not exist or is empty.
func ingestGraphFindings(dir string) ([]findings.CompoundFinding, error) {
	info, statErr := os.Stat(dir)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat graph findings dir: %w", statErr)
	}
	if !info.IsDir() {
		return nil, nil
	}

	var result []findings.CompoundFinding
	for relation, spec := range graphChainRegistry {
		path := filepath.Join(dir, relation+".csv")
		tuples, err := readTSVFile(path)
		if err != nil {
			continue
		}
		for lineIdx, cols := range tuples {
			if spec.Columns > 0 && len(cols) < spec.Columns {
				slog.Warn("graph-findings: malformed Soufflé output line",
					"relation", relation, "line", lineIdx+1,
					"got", len(cols), "want", spec.Columns)
				continue
			}
			resourceID := spec.Resource(cols)
			cf := findings.CompoundFinding{
				FindingID:     findings.StableChainFindingID(spec.ChainID, resourceID, "graph"),
				ChainID:       spec.ChainID,
				AssetID:       resourceID,
				Description:   spec.Description,
				Severity:      spec.Severity,
				Narrative:     spec.Narrative(cols),
				AttackStages:  spec.Stages,
				CompoundScore: severityScore(spec.Severity),
			}
			result = append(result, cf)
		}
	}

	// Warn about .csv files that have no registry entry — a new
	// Soufflé rule without a matching spec produces invisible findings.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".csv") {
			continue
		}
		relation := strings.TrimSuffix(e.Name(), ".csv")
		if _, ok := graphChainRegistry[relation]; !ok {
			slog.Warn("graph-findings: unregistered Soufflé relation — findings will not appear in output",
				"relation", relation, "file", e.Name())
		}
	}

	return result, nil
}

func readTSVFile(path string) ([][]string, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	defer f.Close()

	var rows [][]string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		rows = append(rows, strings.Split(line, "\t"))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", filepath.Base(path), err)
	}
	return rows, nil
}

func severityScore(s policy.Severity) float64 {
	switch s {
	case policy.SeverityCritical:
		return 1.0
	case policy.SeverityHigh:
		return 0.8
	case policy.SeverityMedium:
		return 0.6
	default:
		return 0.4
	}
}

func col(cols []string, i int) string {
	if i < len(cols) {
		return cols[i]
	}
	return ""
}

// markDegradedGraphEdges flags graph findings that reference assets with
// is_expired=true or is_dormant=true in the latest snapshot. These assets
// represent trust relationships that may not be exploitable.
func markDegradedGraphEdges(gf []findings.CompoundFinding, snapshots []asset.Snapshot) {
	if len(gf) == 0 || len(snapshots) == 0 {
		return
	}
	latest := snapshots[len(snapshots)-1]
	degraded := make(map[asset.ID]string)
	for i := range latest.Assets {
		a := &latest.Assets[i]
		if v, _ := a.Properties["is_expired"].(bool); v {
			degraded[a.ID] = "referenced asset has is_expired=true"
		} else if v, _ := a.Properties["is_dormant"].(bool); v {
			degraded[a.ID] = "referenced asset has is_dormant=true"
		}
	}
	if len(degraded) == 0 {
		return
	}
	for i := range gf {
		if reason, ok := degraded[gf[i].AssetID]; ok {
			gf[i].DegradedEdge = true
			gf[i].DegradedEdgeReason = reason
		}
	}
}
