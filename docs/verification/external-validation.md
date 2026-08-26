# Validating Stave Findings with External Tools

## Why External Validation Matters

Stave evaluates cloud configuration snapshots. It reads what
the API says the configuration IS. An external network scanner
tests what the network actually DOES.

These are different questions:

- Stave: "Does the security group configuration restrict
  inbound access to port 22?"
- Scanner: "Can I reach port 22 from outside the VPC?"

Both should agree. If they don't, one of three things is wrong:

1. The control's predicate missed a condition (file a bug)
2. The collector didn't capture a relevant field (file a bug)
3. The configuration is correct but another path exists that
   the control doesn't cover (file a coverage gap)

In all three cases, the disagreement is the signal.

## The Validation Flow

```
Step 1: Deploy infrastructure (lab or production)
         |
Step 2: stave apply --observations <snapshot-dir>
         |
         +-- Stave says: "these network properties hold"
         |
Step 3: Run a network scanner against the same environment
         |
         +-- Scanner says: "these services are reachable"
         |
Step 4: Compare
         |
         +-- Agreement: confidence earned
         +-- Disagreement: file a bug with both outputs
```

## Using Cygor

[Cygor](https://github.com/tjnull/cygor) is an open-source modular
asset discovery framework. It scans networks, enumerates services,
and reports what is reachable. Apache 2.0 licensed.

### Install

```bash
pipx install cygor
```

### Step 1: Run Stave

```bash
stave apply --observations observations/ --format json > findings.json
```

Record which network controls passed and which fired.

### Step 2: Identify Network Controls to Validate

Filter Stave findings to network-layer controls:

```bash
cat findings.json | jq '[.findings[] | select(
  .control_id | test("SG\\.|NACL\\.|VPC\\.|TGW\\.|EGRESS\\.|DNS")
)]'
```

Also note controls that PASSED — those are the claims to test.
A passing control says "this network property holds." The scanner
tests whether it actually does.

### Step 3: Run Cygor Against the Same Environment

```bash
# Discover hosts in the VPC CIDR range
cygor scan -i eth0 -f vpc-cidrs.txt --discover naabu

# Enumerate services on discovered hosts
cygor enum lockon web -f results/parsed-hostlists/http/http-hostlist.txt
```

Run the scan FROM the perspective the control is protecting
against:

- For ingress controls: scan from outside the VPC (a different
  VPC, your workstation, or the internet depending on the
  control's scope)
- For egress controls: scan from inside the VPC outward
  (deploy a test instance inside the restricted subnet)
- For cross-VPC controls (TGW): scan from one VPC toward
  another that should be isolated

### Step 4: Compare Results

| Stave Says | Scanner Says | Meaning |
|------------|-------------|---------|
| Control PASSED (port restricted) | Port NOT reachable | Agreement. Confidence earned. |
| Control PASSED (port restricted) | Port IS reachable | Disagreement. File a bug. |
| Control FIRED (port exposed) | Port IS reachable | Agreement. Finding is correct. |
| Control FIRED (port exposed) | Port NOT reachable | Possible false positive. Investigate. |

### Step 5: File a Bug (When They Disagree)

If Stave says a property holds and the scanner proves it doesn't,
file a bug with:

1. The Stave finding (or lack of finding) — control ID, asset,
   pass/fail status
2. The scanner evidence — the reachability proof (port open,
   service banner, screenshot)
3. The infrastructure state — the security group rules, NACL
   entries, or route table that should have prevented access

This gives maintainers a reproducible case: the expected behavior
(control should fire), the actual behavior (control passed), and
the proof (the scanner reached the service).

## What To Validate

Not every Stave control has a scanner-testable counterpart.
Network-layer controls are the best candidates:

### High-Value Validation Targets

- Security group ingress/egress rules (SG controls)
- NACL allow/deny rules
- VPC endpoint policies (can an unauthorized principal
  reach the endpoint?)
- TGW route isolation (can traffic cross VPC boundaries
  that should be isolated?)
- DNS firewall rules (can a workload resolve blocked domains?)
- Egress restrictions (can a workload reach the internet
  when it shouldn't?)

### Not Scanner-Testable

- IAM policy evaluation (identity-layer, not network-layer)
- KMS key rotation (configuration property, not reachability)
- S3 bucket policies (API-layer, not network-layer — though
  you can test with `aws s3 ls` from an unauthorized context)
- CloudTrail logging (existence check, not reachability)

## Other Scanners

Cygor is one option. The same validation flow works with any
network scanner:

- nmap (manual, single-host)
- masscan (fast, large scope)
- naabu (simple TCP port scan)
- prowler (AWS-specific, overlaps with Stave's scope but
  tests from a different angle)

The tool doesn't matter. The comparison does. Stave's claim
vs the scanner's evidence. Agreement or disagreement.
