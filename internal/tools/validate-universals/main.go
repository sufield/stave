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

// 27 scorecard universals (U1-U20 minus U16/N/A, plus U26-U33).
var universals = []universal{
	{"U1", "Least privilege", []string{".ADMIN.", ".WILDCARD.", ".SERVICEWILDCARD."}},
	{"U2", "No long-lived credentials", []string{".CRED.", ".TTL.", ".UNUSED."}},
	{"U3", "MFA enforcement", []string{".MFA."}},
	{"U4", "No root account usage", []string{".ROOT."}},
	{"U5", "Block public access", []string{".PUBLIC.", ".PAB."}},
	{"U6", "Default deny on network", []string{".SG.", ".NACL."}},
	{"U7", "No management ports open", []string{".RESTRICTED.PORTS.", ".SSH."}},
	{"U8", "Encryption at rest", []string{".ENCRYPT.", ".SSE.", ".KMS."}},
	{"U9", "Encryption in transit", []string{".TRANSIT.", ".TLS.", ".HTTPS."}},
	{"U10", "KMS key rotation", []string{".ROTATION."}},
	{"U11", "CloudTrail enabled", []string{".CLOUDTRAIL."}},
	{"U12", "Resource-specific logging", []string{".LOG."}},
	{"U13", "Log integrity", []string{".VALIDATION.", ".INTEGRITY."}},
	{"U14", "AWS Config enabled", []string{".CONFIG."}},
	{"U15", "Configuration drift detection", []string{".DRIFT.", ".SNAPSHOT.STALE."}},
	{"U17", "No plaintext secrets", []string{".SECRET.", ".SECRETS.", ".CREDS.", ".ENV.ENCRYPT."}},
	{"U18", "Secrets rotation", []string{".ROTATION."}},
	{"U19", "SCPs active", []string{".ORG."}},
	{"U20", "Environment isolation", []string{".CROSSACCOUNT.", ".CROSS.ENV."}},
	{"U26", "Service-level logging", []string{".LOG.", ".AUDIT.", ".LOGGING.", ".NOLOGGING."}},
	{"U27", "Endpoint authentication", []string{".AUTH.", ".NOAUTH."}},
	{"U28", "Deletion protection", []string{".DELETEPROT.", ".DELETION."}},
	{"U29", "Backup configured", []string{".BACKUP.", ".PITR.", ".RECOVERY."}},
	{"U30", "No plaintext secrets in config", []string{".SECRET.", ".SECRETS.", ".CREDS.", ".ENV.ENCRYPT."}},
	{"U31", "Version currency", []string{".VERSION.", ".RUNTIME.", ".ENGINE.", ".EOL."}},
	{"U32", "IMDSv2 enforced", []string{".IMDSV2.", ".IMDS."}},
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
		"--format", "json")
	cmd.Stderr = os.Stderr
	rawOut, _ := cmd.Output()
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
