# Bridgewater Audit Gap Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close 4 partially-answered items from the Bridgewater re:Inforce audit: Q8 (data zone identification chain), Q9 (cross-VPC transitive reachability in the network proof engine), Q21 (cross-account network reachability via TGW edges in the graph), Q22 (sensitive resource without controls chain).

**Architecture:** Q8 and Q22 are new chain YAML files — no Go code. Q9 and Q21 extend the existing `internal/core/network/` proof engine: add Transit Gateway and cross-account peering edges to the graph, then add a `ProveTransitiveSSH` proof property that walks multi-hop paths. The existing `CanReach` already handles cross-VPC peering; the gap is TGW routing and N-hop traversal.

**Tech Stack:** Go (network proof engine), YAML (chain definitions), existing test patterns in `proof_test.go`.

---

## File Structure

| File | Responsibility | Action |
|------|----------------|--------|
| `internal/chaindata/embedded/s3_data_zone_gap.yaml` | Q8: chain combining VPC endpoint + subnet controls | Create |
| `internal/chaindata/embedded/sensitive_uncovered.yaml` | Q22: chain for sensitive resource without controls | Create |
| `internal/core/network/types.go` | GraphTypes struct — add TransitGateway | Modify |
| `internal/core/network/graph.go` | Graph struct + extractors — add TGW attachments, TransitGateway routes, cross-account peering edges | Modify |
| `internal/core/network/reachability.go` | `CanReach` — add TGW-mediated reachability | Modify |
| `internal/core/network/proof.go` | Add `ProveTransitiveSSH` — N-hop SSH traversal | Modify |
| `internal/core/network/proof_test.go` | Tests for transitive SSH and TGW reachability | Modify |
| `pkg/stave/network.go` | Wire `transitive-ssh` property into switch | Modify |
| `cmd/network/prove/options.go` | Add `transitive-ssh` to help text | Modify |

---

### Task 1: Q8 — Data Zone Identification Chain

A chain that fires when a VPC endpoint exists with a permissive policy AND a subnet has instances with broad IAM roles — the "data zone" where S3 is reachable but not locked down.

**Files:**
- Create: `internal/chaindata/embedded/s3_data_zone_gap.yaml`

- [ ] **Step 1: Write the chain YAML**

```yaml
id: s3_data_zone_gap
description: >
  VPC endpoint permits S3 access AND subnet instances have
  broad IAM roles — the combination defines a "data zone"
  where any workload can reach S3 through the endpoint with
  no policy restriction. The endpoint exists (billable,
  visible in the inventory) but does not constrain which
  principals or buckets are reachable, while the instances
  in the same network path have over-privileged IAM roles
  that grant wide S3 access. Neither fact alone is critical;
  together they describe an uncontrolled data-access path
  from compute to storage through a network primitive that
  was presumably deployed FOR control.
controls:
  - CTL.VPC.ENDPOINT.GATEWAY.DEFAULTPOLICY.001
  - CTL.VPC.ENDPOINT.POLICY.WILDCARD.001
  - CTL.VPC.ENDPOINT.BUCKET.RESTRICT.001
  - CTL.EC2.PROFILE.OVERBROAD.001
  - CTL.IAM.POLICY.SERVICEWILDCARD.001
escalation_threshold: 2
compound_severity: high
preconditions:
  - vpc_instance_compromise
postconditions:
  - s3_data_access
implicit_dependencies: []
```

- [ ] **Step 2: Validate the chain loads**

Run: `cd stave && go build ./... && ./stave apply --observations internal/fixtures/labs/org-governance/ungoverned/ --eval-time 2026-08-01T15:00:00Z --format json 2>/dev/null | jq '.chains // empty'`
Expected: build succeeds. Chain loads without parse error.

- [ ] **Step 3: Commit**

```bash
git add internal/chaindata/embedded/s3_data_zone_gap.yaml
git commit -m "feat(chains): add s3_data_zone_gap chain (Bridgewater Q8)"
```

---

### Task 2: Q22 — Sensitive Resource Without Controls Chain

A chain that fires when a resource is tagged as sensitive/confidential but lacks encryption, access logging, or public access blocking.

**Files:**
- Create: `internal/chaindata/embedded/sensitive_uncovered.yaml`

- [ ] **Step 1: Write the chain YAML**

```yaml
id: sensitive_uncovered
description: >
  Resource tagged as sensitive or confidential lacks
  corresponding protective controls. The tagging system
  identifies the resource as high-value, but encryption,
  access logging, or public access blocking are missing.
  The classification exists — someone decided this resource
  matters — but the controls that should follow from that
  classification are absent. The tag is a promise; the
  missing controls are the broken promise.
controls:
  - CTL.TAGGING.CLASSIFICATION.001
  - CTL.S3.ENCRYPTION.001
  - CTL.S3.PAB.001
  - CTL.S3.LOGGING.001
  - CTL.RDS.ENCRYPTION.001
  - CTL.EBS.ENCRYPTION.001
escalation_threshold: 2
compound_severity: high
preconditions:
  - data_classification_exists
postconditions:
  - sensitive_data_exposure
implicit_dependencies: []
```

- [ ] **Step 2: Validate the chain loads**

Run: `cd stave && go build ./... && ./stave apply --observations internal/fixtures/labs/org-governance/ungoverned/ --eval-time 2026-08-01T15:00:00Z --format json 2>/dev/null | jq '.chains // empty'`
Expected: build succeeds. Chain loads without parse error.

- [ ] **Step 3: Commit**

```bash
git add internal/chaindata/embedded/sensitive_uncovered.yaml
git commit -m "feat(chains): add sensitive_uncovered chain (Bridgewater Q22)"
```

---

### Task 3: Q21 — Add Transit Gateway Edges to Network Graph

Extend the graph builder to model Transit Gateway attachments so cross-account/cross-VPC reachability via TGW is visible to the proof engine.

**Files:**
- Modify: `internal/core/network/types.go`
- Modify: `internal/core/network/graph.go`

- [ ] **Step 1: Write the failing test for TGW extraction**

Add to `internal/core/network/proof_test.go`:

```go
func TestBuildGraph_TGWAttachments(t *testing.T) {
	snap := tgwSnapshot()
	g := BuildGraph([]asset.Snapshot{snap})

	if len(g.TGWAttachments) != 2 {
		t.Fatalf("expected 2 TGW attachments, got %d", len(g.TGWAttachments))
	}
	if !g.vpcsConnectedViaTGW("vpc-prod", "vpc-shared") {
		t.Error("expected vpc-prod and vpc-shared connected via TGW")
	}
}

func tgwSnapshot() asset.Snapshot {
	return buildSnapshot(
		hostAsset("i-prod-01", "vpc-prod", "subnet-a", []string{"sg-prod"}, map[string]string{"stave:environment": "production"}),
		hostAsset("i-shared-01", "vpc-shared", "subnet-b", []string{"sg-shared"}, map[string]string{"stave:environment": "production"}),
		tgwAttachmentAsset("tgw-attach-1", "tgw-001", "vpc-prod"),
		tgwAttachmentAsset("tgw-attach-2", "tgw-001", "vpc-shared"),
	)
}

func tgwAttachmentAsset(id, tgwID, vpcID string) testAsset {
	return testAsset{
		id:       id,
		assetType: "aws_ec2_transit_gateway_vpc_attachment",
		properties: map[string]any{
			"network": map[string]any{
				"transit_gateway": map[string]any{
					"transit_gateway_id": tgwID,
					"vpc_id":             vpcID,
				},
			},
		},
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd stave && go test ./internal/core/network/ -run TestBuildGraph_TGWAttachments -v`
Expected: FAIL — `TGWAttachments` field and `vpcsConnectedViaTGW` method don't exist.

- [ ] **Step 3: Add TransitGateway to GraphTypes**

In `internal/core/network/types.go`, add the field:

```go
var GraphTypes struct {
	Instance          string
	SecurityGroup     string
	PeeringConnection string
	Subnet            string
	RouteTable        string
	Firewall          string
	TransitGateway    string
}
```

- [ ] **Step 4: Add TGW fields to Graph and extraction logic**

In `internal/core/network/graph.go`, add to the `Graph` struct:

```go
type TGWAttachment struct {
	AttachmentID     string
	TransitGatewayID string
	VPCID            string
}
```

Add `TGWAttachments []TGWAttachment` to the `Graph` struct.

Add the case to `BuildGraph`:

```go
case GraphTypes.TransitGateway:
	if GraphTypes.TransitGateway != "" {
		g.extractTGWAttachment(a)
	}
```

Add the extractor:

```go
func (g *Graph) extractTGWAttachment(a *asset.Asset) {
	if tgw, ok := nested(a.Properties, "network", "transit_gateway"); ok {
		att := TGWAttachment{AttachmentID: string(a.ID)}
		att.TransitGatewayID, _ = tgw["transit_gateway_id"].(string)
		att.VPCID, _ = tgw["vpc_id"].(string)
		g.TGWAttachments = append(g.TGWAttachments, att)
	}
}
```

Add the lookup:

```go
func (g *Graph) vpcsConnectedViaTGW(vpc1, vpc2 string) bool {
	tgws := make(map[string][]string) // tgw_id -> []vpc_id
	for _, att := range g.TGWAttachments {
		tgws[att.TransitGatewayID] = append(tgws[att.TransitGatewayID], att.VPCID)
	}
	for _, vpcs := range tgws {
		has1, has2 := false, false
		for _, v := range vpcs {
			if v == vpc1 { has1 = true }
			if v == vpc2 { has2 = true }
		}
		if has1 && has2 {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd stave && go test ./internal/core/network/ -run TestBuildGraph_TGWAttachments -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/core/network/types.go internal/core/network/graph.go internal/core/network/proof_test.go
git commit -m "feat(network): add transit gateway attachments to graph (Bridgewater Q21)"
```

---

### Task 4: Q21 — Wire TGW Reachability into CanReach

Extend `CanReach` and `canReachAnyPort` so that two hosts in different VPCs connected via the same Transit Gateway are considered reachable (same logic as existing VPC peering).

**Files:**
- Modify: `internal/core/network/reachability.go`
- Modify: `internal/core/network/proof_test.go`

- [ ] **Step 1: Write the failing test for TGW reachability**

Add to `proof_test.go`:

```go
func TestCanReach_TGW(t *testing.T) {
	g := &Graph{
		Hosts: map[string]*Host{
			"i-vpc-a": {ID: "i-vpc-a", VPCID: "vpc-a", SGIDs: []string{"sg-a"}, Tags: map[string]string{}},
			"i-vpc-b": {ID: "i-vpc-b", VPCID: "vpc-b", SGIDs: []string{"sg-b"}, Tags: map[string]string{}},
		},
		SGRules: map[string][]SGRule{
			"sg-b": {{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "10.0.0.0/8"}},
		},
		TGWAttachments: []TGWAttachment{
			{AttachmentID: "tgw-att-1", TransitGatewayID: "tgw-001", VPCID: "vpc-a"},
			{AttachmentID: "tgw-att-2", TransitGatewayID: "tgw-001", VPCID: "vpc-b"},
		},
	}

	ok, pathType := g.CanReach("i-vpc-a", "i-vpc-b", 22)
	if !ok {
		t.Fatal("expected TGW-connected hosts to be reachable")
	}
	if pathType != "cross-vpc" {
		t.Errorf("expected path type cross-vpc, got %s", pathType)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd stave && go test ./internal/core/network/ -run TestCanReach_TGW -v`
Expected: FAIL — `TGWAttachments` not checked in `CanReach`, hosts not reachable.

- [ ] **Step 3: Extend CanReach with TGW path**

In `internal/core/network/reachability.go`, modify the cross-VPC block in `CanReach` (after line 55) to also check TGW connectivity:

```go
// Cross-VPC via peering or Transit Gateway.
if src.VPCID != "" && dst.VPCID != "" && src.VPCID != dst.VPCID {
	if g.vpcsArePeered(src.VPCID, dst.VPCID) || g.vpcsConnectedViaTGW(src.VPCID, dst.VPCID) {
```

Apply the same change in `canReachAnyPort` (after line 166):

```go
if g.vpcsArePeered(src.VPCID, dst.VPCID) || g.vpcsConnectedViaTGW(src.VPCID, dst.VPCID) {
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd stave && go test ./internal/core/network/ -run TestCanReach_TGW -v`
Expected: PASS

- [ ] **Step 5: Run full network test suite**

Run: `cd stave && go test ./internal/core/network/ -v`
Expected: All existing tests pass. No regressions.

- [ ] **Step 6: Commit**

```bash
git add internal/core/network/reachability.go internal/core/network/proof_test.go
git commit -m "feat(network): wire TGW connectivity into CanReach (Bridgewater Q21)"
```

---

### Task 5: Q9 — Transitive SSH Proof Property

Add `ProveTransitiveSSH` — finds multi-hop SSH paths where host A can SSH to host B, and host B can SSH to host C (production). This is Tiros's `can_ssh_tunnel` equivalent.

**Files:**
- Modify: `internal/core/network/proof.go`
- Modify: `internal/core/network/proof_test.go`

- [ ] **Step 1: Write the failing test for transitive SSH**

Add to `proof_test.go`:

```go
func TestProveTransitiveSSH_SAT(t *testing.T) {
	// hop1: external -> jumpbox (sg allows 0.0.0.0/0:22)
	// hop2: jumpbox -> prod (sg allows sg-jump:22)
	// This is a 2-hop path: internet -> jumpbox -> prod.
	// jumpbox is NOT tagged as bastion, so it's an unintended relay.
	g := &Graph{
		Hosts: map[string]*Host{
			"i-jump": {ID: "i-jump", VPCID: "vpc-prod", SGIDs: []string{"sg-jump"}, Tags: map[string]string{}},
			"i-prod": {ID: "i-prod", VPCID: "vpc-prod", SGIDs: []string{"sg-prod"}, Tags: map[string]string{"stave:environment": "production"}},
		},
		SGRules: map[string][]SGRule{
			"sg-jump": {{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "0.0.0.0/0"}},
			"sg-prod": {{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-jump"}},
		},
		Subnets:   make(map[string]*Subnet),
		Routes:    make(map[string][]Route),
		Firewalls: make(map[string]bool),
	}

	result, err := g.ProveTransitiveSSH(22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "SAT" {
		t.Fatalf("expected SAT (transitive path exists), got %s", result.Result)
	}
	if result.Counterexample == nil {
		t.Fatal("expected counterexample")
	}
}

func TestProveTransitiveSSH_UNSAT(t *testing.T) {
	// Only direct bastion -> prod path. No relay hosts.
	g := &Graph{
		Hosts: map[string]*Host{
			"i-bastion": {ID: "i-bastion", VPCID: "vpc-prod", SGIDs: []string{"sg-bastion"}, Tags: map[string]string{"stave:role": "bastion", "stave:environment": "production"}},
			"i-prod":    {ID: "i-prod", VPCID: "vpc-prod", SGIDs: []string{"sg-prod"}, Tags: map[string]string{"stave:environment": "production"}},
		},
		SGRules: map[string][]SGRule{
			"sg-bastion": {{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "0.0.0.0/0"}},
			"sg-prod":    {{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-bastion"}},
		},
		Subnets:   make(map[string]*Subnet),
		Routes:    make(map[string][]Route),
		Firewalls: make(map[string]bool),
	}

	result, err := g.ProveTransitiveSSH(22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "UNSAT" {
		t.Fatalf("expected UNSAT (no transitive relay), got %s: %s", result.Result, result.Counterexample.Explanation)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd stave && go test ./internal/core/network/ -run TestProveTransitiveSSH -v`
Expected: FAIL — `ProveTransitiveSSH` does not exist.

- [ ] **Step 3: Implement ProveTransitiveSSH**

Add to `internal/core/network/proof.go`:

```go
// ProveTransitiveSSH checks whether any non-bastion host can act
// as an SSH relay to reach production. Returns SAT if a 2+ hop
// path exists (internet/host → relay → production), where the
// relay is not a designated bastion.
func (g *Graph) ProveTransitiveSSH(port int) (*ProofResult, error) {
	start := time.Now()

	prod := g.ProductionHosts()
	if len(prod) == 0 {
		return nil, fmt.Errorf("%w: no hosts tagged stave:environment=production", ErrVacuousProof)
	}

	bastionIDs := make(map[string]bool)
	for _, b := range g.BastionHosts() {
		bastionIDs[b.ID] = true
	}

	result := &ProofResult{
		Property:        "transitive-ssh",
		ProductionHosts: len(prod),
		BastionHosts:    len(bastionIDs),
	}

	// For each production host, find relay hosts that can reach it
	// and are themselves reachable from outside (internet or another host).
	for _, dst := range prod {
		for _, relay := range g.allHosts() {
			if relay.ID == dst.ID || relay.IsProduction() || bastionIDs[relay.ID] {
				continue
			}
			// Can relay reach production?
			relayToProd, _ := g.CanReach(relay.ID, dst.ID, port)
			if !relayToProd {
				continue
			}
			// Is relay itself reachable from the internet?
			if ce := g.findExternalBypass(relay, port); ce != nil {
				result.Result = "SAT"
				result.Interpretation = "Transitive SSH path exists — a non-bastion host relays SSH to production."
				result.Counterexample = &Counterexample{
					Source:      "0.0.0.0/0 → " + relay.ID,
					Destination: dst.ID,
					Port:        port,
					PathType:    "transitive",
					RuleSG:      ce.RuleSG,
					RuleSource:  ce.RuleSource,
					Explanation: "Internet can SSH to " + relay.ID + " (not a bastion), which can SSH to production host " + dst.ID + ". Two-hop relay bypasses bastion architecture.",
					Remediation: "Remove SSH ingress from 0.0.0.0/0 on " + relay.ID + "'s SG, or restrict production SG to bastion references only.",
				}
				result.SolveTimeMs = time.Since(start).Milliseconds()
				return result, nil
			}
			// Is relay reachable from any other non-production, non-bastion host?
			for _, src := range g.allHosts() {
				if src.ID == relay.ID || src.ID == dst.ID || src.IsProduction() || bastionIDs[src.ID] {
					continue
				}
				if ok, _ := g.CanReach(src.ID, relay.ID, port); ok {
					ruleSG, ruleSource := g.findRule(src, relay, port)
					result.Result = "SAT"
					result.Interpretation = "Transitive SSH path exists — a non-bastion host relays SSH to production."
					result.Counterexample = &Counterexample{
						Source:      src.ID + " → " + relay.ID,
						Destination: dst.ID,
						Port:        port,
						PathType:    "transitive",
						RuleSG:      ruleSG,
						RuleSource:  ruleSource,
						Explanation: "Host " + src.ID + " can SSH to " + relay.ID + " (not a bastion), which can SSH to production host " + dst.ID + ". Multi-hop relay bypasses bastion architecture.",
						Remediation: "Restrict SSH ingress on " + relay.ID + "'s SG. Only bastion hosts should relay SSH to production.",
					}
					result.SolveTimeMs = time.Since(start).Milliseconds()
					return result, nil
				}
			}
		}
	}

	result.Result = "UNSAT"
	result.Interpretation = "No transitive SSH relay paths to production — all multi-hop SSH paths pass through designated bastions."
	result.SolveTimeMs = time.Since(start).Milliseconds()
	return result, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd stave && go test ./internal/core/network/ -run TestProveTransitiveSSH -v`
Expected: Both PASS.

- [ ] **Step 5: Run full network test suite**

Run: `cd stave && go test ./internal/core/network/ -v`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/core/network/proof.go internal/core/network/proof_test.go
git commit -m "feat(network): add transitive-ssh proof property (Bridgewater Q9)"
```

---

### Task 6: Wire transitive-ssh into CLI

Add `transitive-ssh` to the `NetworkProve` switch and update the help text.

**Files:**
- Modify: `pkg/stave/network.go`
- Modify: `cmd/network/prove/options.go`

- [ ] **Step 1: Add the case to pkg/stave/network.go**

In the `NetworkProve` function's switch statement, add:

```go
case "transitive-ssh":
	r, err = g.ProveTransitiveSSH(cfg.Port)
```

Update the error message to include `transitive-ssh`:

```go
return nil, fmt.Errorf("network prove: unknown property %q (valid: bastion-ssh, prod-dev-isolation, database-isolation, firewall-mandatory, transitive-ssh)", cfg.Property)
```

- [ ] **Step 2: Update help text in cmd/network/prove/options.go**

Find the property flag help and add `transitive-ssh` to the list. Expected location: the `--property` flag definition.

- [ ] **Step 3: Build and verify**

Run: `cd stave && go build ./... && ./stave network prove --help 2>&1 | grep transitive`
Expected: `transitive-ssh` appears in help output.

- [ ] **Step 4: Run full test suite**

Run: `cd stave && make test`
Expected: All tests pass.

- [ ] **Step 5: Run lint**

Run: `cd stave && make lint`
Expected: 0 issues.

- [ ] **Step 6: Commit**

```bash
git add pkg/stave/network.go cmd/network/prove/options.go
git commit -m "feat(cli): wire transitive-ssh proof property into network prove command"
```

---

### Task 7: Update Audit Scorecard

Update the Bridgewater audit scorecard to reflect the closed gaps.

**Files:**
- Modify: `docs-internal/gap-audits/bridgewater-reinforce-2026-08.md`

- [ ] **Step 1: Update Q8, Q9, Q21, Q22 verdicts**

Change Q8 from PARTIALLY ANSWERED to ANSWERED — evidence: `s3_data_zone_gap` chain.

Change Q9 from PARTIALLY ANSWERED to ANSWERED — evidence: `stave network prove --property transitive-ssh`.

Change Q21 from PARTIALLY ANSWERED to ANSWERED — evidence: TGW edges in network graph, `vpcsConnectedViaTGW` in reachability.

Change Q22 from PARTIALLY ANSWERED to ANSWERED — evidence: `sensitive_uncovered` chain.

Update the summary counts: 0 PARTIALLY, 0 GAP, 19 ANSWERED/EXCEEDED total.

- [ ] **Step 2: Commit**

```bash
git add docs-internal/gap-audits/bridgewater-reinforce-2026-08.md
git commit -m "docs: update Bridgewater audit scorecard — all gaps closed"
```

---

### Task 8: Regenerate Goldens and Final Verification

- [ ] **Step 1: Regenerate goldens**

Run: `cd stave && make regenerate-goldens`
Expected: Any new chain firing produces FINGERPRINT-ONLY or METADATA-ONLY diffs (safe to commit).

- [ ] **Step 2: Run full CI check**

Run: `cd stave && make ci`
Expected: All checks pass.

- [ ] **Step 3: Run consistency check**

Run: `cd stave && make consistency-check`
Expected: No drift.

- [ ] **Step 4: Commit any golden changes**

```bash
git add -A
git commit -m "test: regenerate goldens after Bridgewater gap closure"
```
