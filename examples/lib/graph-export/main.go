//go:build graphexample

// Command graph-export demonstrates pkg/stave.ExportGraph — projecting a
// Stave Assessment into the cross-service relationship view (assets, the
// findings and chains that hang off them, and the edges between), both in
// its basic form and enriched with a SIR document via WithSIRDocument.
//
// The build tag keeps this out of the normal module build. Run it with:
//
//	cd stave
//	go run -tags graphexample ./examples/lib/graph-export
//
// See README.md in this directory for what each field means and how
// downstream tools (Neo4j visualisers, Z3 reachability queries) consume it.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/sufield/stave/internal/core/sir"
	"github.com/sufield/stave/pkg/stave"
)

func main() {
	a := sampleAssessment()

	// 1. Basic export — everything derivable from the Assessment alone:
	//    deduplicated AssetNodes, one FindingNode per finding, ChainNodes,
	//    and the finding_about / chain_member edges between them.
	basic := stave.ExportGraph(a)
	dump("ExportGraph(assessment)", basic)

	// 2. Enriched export — hydrate the graph with transitive role chains and
	//    per-asset lifecycle drawn from a SIR document. In a real pipeline the
	//    SIR doc is the one an Apply run already built for fact-id correlation;
	//    here we hand-build a tiny one to show the shape WithSIRDocument reads.
	enriched := stave.ExportGraph(a, stave.WithSIRDocument(sampleSIR()))
	dump("ExportGraph(assessment, WithSIRDocument(doc))", enriched)
}

// sampleAssessment builds a two-finding assessment on one bucket, with one
// finding participating in a compound chain. A real consumer obtains an
// *Assessment from stave.Apply, stave.LoadAssessment, or stave.FromReportAssessment.
func sampleAssessment() *stave.Assessment {
	return &stave.Assessment{
		Findings: []stave.Finding{
			{
				FindingID:     "fid-public-acl",
				ControlID:     "CTL.S3.ACCESS.001",
				AssetID:       "arn:aws:s3:::data-bucket",
				AssetType:     "aws_s3_bucket",
				Severity:      "high",
				ExposureScore: 7.5,
				// Membership marks this finding as part of a compound chain;
				// ExportGraph emits a chain_member edge for it.
				ChainMembership: []stave.ChainMembershipEntry{{ChainID: "data_exfil_path"}},
			},
			{
				FindingID:     "fid-open-policy",
				ControlID:     "CTL.S3.ACCESS.004",
				AssetID:       "arn:aws:s3:::data-bucket",
				AssetType:     "aws_s3_bucket",
				Severity:      "high",
				ExposureScore: 8.0,
			},
		},
		ChainFindings: []stave.ChainFinding{
			{
				ChainID:         "data_exfil_path",
				Severity:        "critical",
				CompoundScore:   9.2,
				ControlsFailing: []stave.ControlID{"CTL.S3.ACCESS.001"},
			},
		},
	}
}

// sampleSIR builds a minimal SIR document: one asset with a lifecycle
// envelope (so AssetNode.Lifecycle populates) and one identity with a
// cross-account role chain (so GraphExport.TransitiveReachability populates).
func sampleSIR() *sir.Document {
	now := time.Now().UTC()
	return &sir.Document{
		Assets: []sir.AssetFact{
			{
				ID:     "arn:aws:s3:::data-bucket",
				Type:   "aws_s3_bucket",
				Vendor: "aws",
				Lifecycle: &sir.AssetLifecycleFact{
					Provisioned: true,
					FirstSeen:   now.Add(-48 * time.Hour),
					LastSeen:    now,
				},
			},
		},
		Identities: []sir.IdentityFact{
			{
				PrincipalID: "arn:aws:iam::111122223333:user/ci-deployer",
				RoleChains: []sir.RoleChainFact{
					{
						FinalRoleARN:      "arn:aws:iam::444455556666:role/prod-admin",
						TransitiveLevel:   "admin",
						TerminationReason: "normal",
						Hops: []sir.RoleHopFact{
							{
								From:         "arn:aws:iam::111122223333:user/ci-deployer",
								To:           "arn:aws:iam::444455556666:role/prod-admin",
								CrossAccount: true,
								HopType:      "assume_role",
							},
						},
					},
				},
			},
		},
	}
}

func dump(title string, g *stave.GraphExport) {
	fmt.Printf("\n=== %s ===\n", title)
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal graph export:", err)
		os.Exit(1)
	}
	fmt.Println(string(b))
}
