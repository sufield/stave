package main

// Real-World Pattern 3 case study from "Exploiting AWS IAM
// permissions for total cloud compromise: a real world
// example" (Security Shenanigans, October 2020).
//
// The writeup proves the iam:PassRole + ec2:RunInstances
// compound is *necessary but not sufficient*. The successful
// escalation also required:
//
//   1. A discoverable admin-equivalent role (iam:ListRoles
//      or iam:GetRole on the target).
//   2. That role trusting ec2.amazonaws.com.
//   3. A security group with egress to the attacker (for the
//      reverse-shell user-data to reach back).
//   4. A subnet in the same VPC as the security group.
//   5. An AMI the attacker can launch (ec2:DescribeImages).
//
// Tools that report "Confirmed — privilege escalation
// possible" on PassRole + RunInstances alone — Rhino's own
// aws_escalate.py among them — produce false positives
// whenever the network configuration disallows reverse-shell
// callback. The Bybit / Safe{WALLET} extension shows the dual
// false-negative on the prefix-wildcard side; this extension
// shows the false-positive side: a script reports "exploitable"
// but the compound is UNSAT.
//
// Z3 encodes the full conjunction. SAT iff every constraint
// is independently satisfied; UNSAT iff any one fails.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aclements/go-z3/z3"
)

type securityGroup struct {
	groupID  string
	name     string
	vpcID    string
	hasEgress bool
}

type subnet struct {
	subnetID string
	vpcID    string
}

type realWorldFixture struct {
	allow         []statement
	deny          []statement
	adminRoles    []adminRole
	securityGroups []securityGroup
	subnets       []subnet
}

func runRealWorldProof(snapshotsDir, label string) bool {
	f, err := loadRealWorldFixture(snapshotsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] load: %v\n", label, err)
		return false
	}

	fmt.Println()
	fmt.Println("====================================================================")
	fmt.Printf("== %s\n", label)
	fmt.Println("====================================================================")
	fmt.Printf("  policy statements: %d allow, %d deny\n", len(f.allow), len(f.deny))
	fmt.Printf("  admin roles:       %d\n", len(f.adminRoles))
	for _, r := range f.adminRoles {
		fmt.Printf("    - %s   trusts=%v   admin=%v\n", r.arn, r.trustedServices, r.isAdmin)
	}
	fmt.Printf("  security groups:   %d\n", len(f.securityGroups))
	for _, sg := range f.securityGroups {
		fmt.Printf("    - %s (%s)   vpc=%s   egress=%v\n", sg.groupID, sg.name, sg.vpcID, sg.hasEgress)
	}
	fmt.Printf("  subnets:           %d\n", len(f.subnets))
	for _, s := range f.subnets {
		fmt.Printf("    - %s   vpc=%s\n", s.subnetID, s.vpcID)
	}

	q1 := queryPattern3CompoundFor(f, "sg-f73b339e", "with default security group (no egress)")
	printRealWorldVerdict("Default SG only (no egress)", q1)

	q2 := queryPattern3CompoundFor(f, "sg-42csce3f", "with hadoop security group (egress allowed)")
	printRealWorldVerdict("Hadoop SG (full egress)", q2)

	q3 := queryPattern3WithoutDiscovery(f)
	printRealWorldVerdict("Without iam:ListRoles (no role discovery)", q3)

	// Assertion: q1 UNSAT, q2 SAT, q3 UNSAT.
	return !q1.sat && q2.sat && !q3.sat
}

type rwVerdict struct {
	sat       bool
	witness   string
	rationale string
	failedAt  string
}

func printRealWorldVerdict(title string, v rwVerdict) {
	fmt.Println()
	fmt.Printf("--- %s ---\n", title)
	if v.sat {
		fmt.Println("  verdict: SAT — full compound satisfied")
	} else {
		fmt.Println("  verdict: UNSAT")
	}
	if v.witness != "" {
		fmt.Printf("  witness: %s\n", v.witness)
	}
	if v.failedAt != "" {
		fmt.Printf("  failed:  %s\n", v.failedAt)
	}
	if v.rationale != "" {
		fmt.Printf("  note:    %s\n", v.rationale)
	}
}

// queryPattern3CompoundFor encodes the full 5-conjunction:
//
//	passrole ∧ run_instances ∧ can_discover_role ∧
//	role_is_admin ∧ role_trusts_ec2 ∧
//	exists_egress_sg(sgID) ∧ exists_valid_subnet
//
// Each clause is a constant Bool derived from the fixture;
// Z3 only adds value here as a witness extractor and as a
// substrate the same model can be re-queried against. The
// modelling discipline is the same as the per-pattern
// queries in main.go.
func queryPattern3CompoundFor(f realWorldFixture, sgID, comment string) rwVerdict {
	ctx := z3.NewContext(nil)

	passrole := actionEffectivelyAllowed("iam:PassRole", fixture{allow: f.allow, deny: f.deny})
	runInstances := actionEffectivelyAllowed("ec2:RunInstances", fixture{allow: f.allow, deny: f.deny})

	// Discovery: ListRoles OR GetRole.
	canList := actionEffectivelyAllowed("iam:ListRoles", fixture{allow: f.allow, deny: f.deny})
	canGet := actionEffectivelyAllowed("iam:GetRole", fixture{allow: f.allow, deny: f.deny})
	canDiscover := canList || canGet

	// Target role exists, is admin, trusts ec2.
	var targetRole *adminRole
	for i, r := range f.adminRoles {
		if !r.isAdmin {
			continue
		}
		for _, svc := range r.trustedServices {
			if svc == "ec2.amazonaws.com" {
				targetRole = &f.adminRoles[i]
				break
			}
		}
		if targetRole != nil {
			break
		}
	}
	roleAdminTrustsEC2 := targetRole != nil

	// Egress SG named by sgID exists and has egress.
	var sg *securityGroup
	for i := range f.securityGroups {
		if f.securityGroups[i].groupID == sgID {
			sg = &f.securityGroups[i]
			break
		}
	}
	canDescribeSGs := actionEffectivelyAllowed("ec2:DescribeSecurityGroups", fixture{allow: f.allow, deny: f.deny})
	hasEgressSG := sg != nil && sg.hasEgress && canDescribeSGs

	// Valid subnet in same VPC as SG.
	canDescribeSubnets := actionEffectivelyAllowed("ec2:DescribeSubnets", fixture{allow: f.allow, deny: f.deny})
	hasValidSubnet := false
	if sg != nil && canDescribeSubnets {
		for _, s := range f.subnets {
			if s.vpcID == sg.vpcID {
				hasValidSubnet = true
				break
			}
		}
	}

	// Encode in Z3 to confirm the conjunction. The Z3 layer
	// here is structurally identical to the main-prover's
	// per-pattern check — every clause is a Bool, the SAT
	// check is the conjunction.
	clauses := []z3.Bool{
		ctx.FromBool(passrole),
		ctx.FromBool(runInstances),
		ctx.FromBool(canDiscover),
		ctx.FromBool(roleAdminTrustsEC2),
		ctx.FromBool(hasEgressSG),
		ctx.FromBool(hasValidSubnet),
	}
	conj := clauses[0].And(clauses[1:]...)
	s := z3.NewSolver(ctx)
	s.Assert(conj)
	sat, err := s.Check()
	if err != nil {
		return rwVerdict{rationale: "z3 error"}
	}

	if !sat {
		return rwVerdict{
			sat:      false,
			failedAt: identifyFailedClause(passrole, runInstances, canDiscover, roleAdminTrustsEC2, hasEgressSG, hasValidSubnet, sg),
			rationale: comment,
		}
	}

	witness := fmt.Sprintf("PassRole→%s + RunInstances + ListRoles + sg=%s + subnet in vpc=%s",
		safeTargetARN(targetRole), sgID, sg.vpcID)
	return rwVerdict{
		sat:       true,
		witness:   witness,
		rationale: comment,
	}
}

// queryPattern3WithoutDiscovery removes the role-discovery
// clause's evidence — same compound, but pretend the user
// has neither ListRoles nor GetRole. Used to demonstrate
// the false-positive an action-list checker produces when
// it ignores the discoverability constraint.
func queryPattern3WithoutDiscovery(f realWorldFixture) rwVerdict {
	ctx := z3.NewContext(nil)

	passrole := actionEffectivelyAllowed("iam:PassRole", fixture{allow: f.allow, deny: f.deny})
	runInstances := actionEffectivelyAllowed("ec2:RunInstances", fixture{allow: f.allow, deny: f.deny})

	// Synthetic: strip discovery from this query's view.
	canDiscover := false

	roleAdminTrustsEC2 := false
	for _, r := range f.adminRoles {
		if !r.isAdmin {
			continue
		}
		for _, svc := range r.trustedServices {
			if svc == "ec2.amazonaws.com" {
				roleAdminTrustsEC2 = true
				break
			}
		}
		if roleAdminTrustsEC2 {
			break
		}
	}

	// Use hadoop SG so we know SG/subnet constraints pass —
	// isolating the discovery failure as the only unsat clause.
	var hadoop *securityGroup
	for i := range f.securityGroups {
		if f.securityGroups[i].groupID == "sg-42csce3f" {
			hadoop = &f.securityGroups[i]
			break
		}
	}
	canDescribeSGs := actionEffectivelyAllowed("ec2:DescribeSecurityGroups", fixture{allow: f.allow, deny: f.deny})
	hasEgressSG := hadoop != nil && hadoop.hasEgress && canDescribeSGs

	canDescribeSubnets := actionEffectivelyAllowed("ec2:DescribeSubnets", fixture{allow: f.allow, deny: f.deny})
	hasValidSubnet := false
	if hadoop != nil && canDescribeSubnets {
		for _, s := range f.subnets {
			if s.vpcID == hadoop.vpcID {
				hasValidSubnet = true
				break
			}
		}
	}

	clauses := []z3.Bool{
		ctx.FromBool(passrole),
		ctx.FromBool(runInstances),
		ctx.FromBool(canDiscover),
		ctx.FromBool(roleAdminTrustsEC2),
		ctx.FromBool(hasEgressSG),
		ctx.FromBool(hasValidSubnet),
	}
	conj := clauses[0].And(clauses[1:]...)
	s := z3.NewSolver(ctx)
	s.Assert(conj)
	sat, err := s.Check()
	if err != nil {
		return rwVerdict{rationale: "z3 error"}
	}

	if sat {
		return rwVerdict{sat: true, witness: "(unexpected — discovery clause should fail)"}
	}
	return rwVerdict{
		sat:       false,
		failedAt:  "role discovery (no iam:ListRoles, no iam:GetRole)",
		rationale: "PassRole on Resource:* is useless without knowing which role to pass — script checkers miss this",
	}
}

func identifyFailedClause(passrole, runInstances, canDiscover, roleAdmin, hasEgress, hasSubnet bool, sg *securityGroup) string {
	switch {
	case !passrole:
		return "iam:PassRole not effectively allowed"
	case !runInstances:
		return "ec2:RunInstances not effectively allowed"
	case !canDiscover:
		return "no iam:ListRoles or iam:GetRole — cannot discover target role"
	case !roleAdmin:
		return "no admin-equivalent role trusting ec2.amazonaws.com"
	case !hasEgress:
		if sg == nil {
			return "named security group not observed in the account"
		}
		return fmt.Sprintf("security group %s has no egress rules — reverse-shell user-data cannot connect back", sg.groupID)
	case !hasSubnet:
		return "no subnet in the security group's VPC"
	default:
		return "(no failure identified)"
	}
}

func safeTargetARN(r *adminRole) string {
	if r == nil {
		return "(no target)"
	}
	return r.arn
}

func loadRealWorldFixture(snapshotsDir string) (realWorldFixture, error) {
	var f realWorldFixture
	entries, err := os.ReadDir(snapshotsDir)
	if err != nil {
		return f, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	seen := map[string]bool{}
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(snapshotsDir, name))
		if err != nil {
			return f, err
		}
		var snap struct {
			Assets []struct {
				ID         string `json:"id"`
				Type       string `json:"type"`
				Properties struct {
					Identity struct {
						TrustedServices   []string `json:"trusted_services"`
						IsAdminEquivalent bool     `json:"is_admin_equivalent"`
						Policies          struct {
							AttachedPolicies []struct {
								Name       string      `json:"name"`
								Statements []statement `json:"statements"`
							} `json:"attached_policies"`
						} `json:"policies"`
					} `json:"identity"`
					SecurityGroup struct {
						GroupID     string `json:"group_id"`
						GroupName   string `json:"group_name"`
						VPCID       string `json:"vpc_id"`
						EgressRules []struct {
							Protocol string `json:"protocol"`
						} `json:"egress_rules"`
					} `json:"security_group"`
					Subnet struct {
						SubnetID string `json:"subnet_id"`
						VPCID    string `json:"vpc_id"`
					} `json:"subnet"`
				} `json:"properties"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(raw, &snap); err != nil {
			return f, err
		}

		for _, a := range snap.Assets {
			if seen[a.ID] {
				continue
			}
			seen[a.ID] = true
			switch a.Type {
			case "aws_iam_user":
				if a.ID != userARN {
					continue
				}
				for _, p := range a.Properties.Identity.Policies.AttachedPolicies {
					for _, st := range p.Statements {
						switch strings.ToUpper(st.Effect) {
						case "ALLOW":
							f.allow = append(f.allow, st)
						case "DENY":
							f.deny = append(f.deny, st)
						}
					}
				}
			case "aws_iam_role":
				f.adminRoles = append(f.adminRoles, adminRole{
					arn:             a.ID,
					trustedServices: a.Properties.Identity.TrustedServices,
					isAdmin:         a.Properties.Identity.IsAdminEquivalent,
				})
			case "aws_ec2_security_group":
				f.securityGroups = append(f.securityGroups, securityGroup{
					groupID:   a.Properties.SecurityGroup.GroupID,
					name:      a.Properties.SecurityGroup.GroupName,
					vpcID:     a.Properties.SecurityGroup.VPCID,
					hasEgress: len(a.Properties.SecurityGroup.EgressRules) > 0,
				})
			case "aws_ec2_subnet":
				f.subnets = append(f.subnets, subnet{
					subnetID: a.Properties.Subnet.SubnetID,
					vpcID:    a.Properties.Subnet.VPCID,
				})
			}
		}
	}
	return f, nil
}
