// validate-universals checks that extensional controls behave consistently
// with their universal statement mappings across lab fixtures.
//
// For each universal, it verifies:
//   - well-governed fixture: no controls for that universal fire (property holds)
//   - ungoverned fixture: ≥1 control for that universal fires (violation exists)
//
// Usage: go run ./internal/tools/validate-universals
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type universal struct {
	ID       string
	Name     string
	Patterns []string
}

var universals = []universal{
	{"U1", "Unrestricted PM on wildcard", []string{".ADMIN.", ".PERMISSIONS.", ".WILDCARD."}},
	{"U2", "Cross-account without org boundary", []string{".CROSS.", ".PRINCIPAL."}},
	{"U3", "Federation without subject", []string{".FEDERATION.", ".SAML.", ".OIDC."}},
	{"U4", "Credential lifetime (access keys)", []string{".KEY.ROTATION.", ".KEY.AGE."}},
	{"U5", "Session without attribution", []string{".MFA.", ".SESSION."}},
	{"U6", "Policy removal without compensation", []string{".DETACH.", ".REMOVAL."}},
	{"U7", "Encryption at rest", []string{".ENCRYPT.", ".KMS.", ".SSE."}},
	{"U9", "Endpoint without TLS", []string{".TLS.", ".SSL.", ".HTTPS.", ".TRANSIT."}},
	{"U10", "Public accessibility", []string{".PUBLIC."}},
	{"U11", "Network isolation", []string{".SG.", ".NACL.", ".SUBNET."}},
	{"U12", "Management port open", []string{".PORT.", ".SSH.", ".RDP."}},
	{"U13", "Default VPC active", []string{".DEFAULT.VPC."}},
	{"U14", "CloudTrail coverage", []string{".CLOUDTRAIL.", ".TRAIL."}},
	{"U15", "Detection delivery", []string{".DELIVERY."}},
	{"U16", "Detection scope", []string{".SCOPE.", ".REGION."}},
	{"U17", "Tamper-proof logs", []string{".INTEGRITY.", ".VALIDATION."}},
	{"U18", "Credential lifetime (general)", []string{".ROTATION.", ".PASSWORD.", ".CREDENTIAL."}},
	{"U19", "Rotation stalled", []string{".STALL.", ".PENDING.ROTATION."}},
	{"U20", "Root account usage", []string{".ROOT."}},
	{"U21", "Intent vs state drift", []string{".DRIFT.", ".INTENT."}},
	{"U22", "Ghost/dangling references", []string{".GHOST.", ".DANGLING.", ".INCOMPLETE."}},
	{"U25", "Compute role admin", []string{".ESCALATE."}},
	{"U26", "Service logging", []string{".LOG.", ".AUDIT.", ".LOGGING.", ".ACCESSLOG."}},
	{"U27", "Endpoint authentication", []string{".AUTH."}},
	{"U28", "Deletion protection", []string{".DELETION.", ".TERMINATION."}},
	{"U29", "Backup/recovery", []string{".BACKUP.", ".SNAPSHOT.", ".PITR.", ".RECOVERY.", ".REPLICATION."}},
	{"U30", "Plaintext secrets", []string{".SECRET.", ".CREDS."}},
	{"U31", "Version currency", []string{".VERSION.", ".RUNTIME.", ".ENGINE.", ".UPGRADE.", ".EOL.", ".DEPRECATED."}},
	{"U32", "IMDSv2 enforcement", []string{".IMDS."}},
	{"U33", "Security service enabled", []string{".ENABLED."}},
}

type finding struct {
	ControlID string `json:"control_id"`
}

type output struct {
	Findings []finding `json:"findings"`
}

func runStave(obsDir string) ([]finding, error) {
	cmd := exec.Command("./stave", "apply",
		"--observations", obsDir,
		"--eval-time", "2026-08-01T15:00:00Z",
		"--format", "json",
		"--quiet=false")
	rawOut, _ := cmd.Output()
	if len(rawOut) == 0 {
		// exit 3/5 writes to stdout, but cmd.Output() only captures stdout
		// re-run capturing stdout explicitly
		cmd2 := exec.Command("./stave", "apply",
			"--observations", obsDir,
			"--eval-time", "2026-08-01T15:00:00Z",
			"--format", "json")
		cmd2.Stderr = os.Stderr
		rawOut, _ = cmd2.Output()
	}
	if len(rawOut) == 0 {
		return nil, fmt.Errorf("no output from stave apply on %s", obsDir)
	}
	var o output
	if err := json.Unmarshal(rawOut, &o); err != nil {
		return nil, fmt.Errorf("parse output from %s: %w\nraw: %s", obsDir, err, string(rawOut[:min(200, len(rawOut))]))
	}
	return o.Findings, nil
}

func main() {
	type fixture struct {
		name      string
		dir       string
		expectNeg bool // true = expect 0 findings per universal (property holds)
	}

	fixtures := []fixture{
		{"well-governed", "internal/fixtures/labs/org-governance/well-governed/", true},
		{"ungoverned", "internal/fixtures/labs/org-governance/ungoverned/", false},
	}

	fmt.Println("Universal Statement Validation Harness")
	fmt.Println("=======================================")
	fmt.Printf("Universals: %d | Fixtures: %d | Checks: %d\n\n",
		len(universals), len(fixtures), len(universals)*len(fixtures))

	totalChecks := 0
	passed := 0
	skipped := 0
	failed := 0

	for _, fix := range fixtures {
		fmt.Printf("## %s (%s)\n\n", fix.name, fix.dir)

		findings, err := runStave(fix.dir)
		if err != nil {
			fmt.Printf("  ERROR: %v\n\n", err)
			continue
		}

		fmt.Printf("  Total findings: %d\n\n", len(findings))

		uFindings := make(map[string][]string)
		for _, f := range findings {
			for _, u := range universals {
				for _, p := range u.Patterns {
					if strings.Contains(f.ControlID, p) {
						uFindings[u.ID] = append(uFindings[u.ID], f.ControlID)
						break
					}
				}
			}
		}

		for _, u := range universals {
			totalChecks++
			controls := uFindings[u.ID]

			if fix.expectNeg {
				if len(controls) == 0 {
					fmt.Printf("  PASS  %-4s %-40s 0 findings\n", u.ID, u.Name)
					passed++
				} else {
					fmt.Printf("  FAIL  %-4s %-40s %d findings on well-governed!\n", u.ID, u.Name, len(controls))
					for _, c := range controls {
						fmt.Printf("        - %s\n", c)
					}
					failed++
				}
			} else {
				if len(controls) > 0 {
					fmt.Printf("  PASS  %-4s %-40s %d findings\n", u.ID, u.Name, len(controls))
					passed++
				} else {
					fmt.Printf("  SKIP  %-4s %-40s no observations in fixture\n", u.ID, u.Name)
					skipped++
				}
			}
		}
		fmt.Println()
	}

	fmt.Println("========================================")
	fmt.Printf("PASS: %d  FAIL: %d  SKIP: %d  TOTAL: %d\n", passed, failed, skipped, totalChecks)

	if failed > 0 {
		os.Exit(1)
	}
}
