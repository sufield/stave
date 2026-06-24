# Capital One (2019) — Stave Demo

The Capital One breach was not one misconfiguration but a **chain**, each link
individually unremarkable:

1. A WAF on an EC2 instance was exploitable via **SSRF**.
2. SSRF reached the instance metadata service (**IMDSv1**) and pulled the
   instance role's temporary credentials.
3. That role had **overly broad S3 read** access.
4. ~100M records were exfiltrated from **S3**.

A per-resource scanner sees three PASSes — "EC2 has a role", "role can read S3",
"service is internet-reachable" — and misses the breach, because the danger is
the **composition**. Stave evaluates the *path*.

Two demos, both runnable from the `stave/` directory.

## Prerequisites

```bash
cd stave
make build          # produces ./stave
```

---

## Demo A — Stave detects the chain (`stave apply`)

Evaluates a committed Capital-One-shaped snapshot against the built-in catalog.
No cloud credentials, no live traffic — a static configuration snapshot in,
findings out.

```bash
cd stave
./stave apply \
  -o examples/demo-capital-one/fixtures/observations \
  -i controls \
  --max-unsafe 168h \
  --now 2019-07-20T00:00:00Z
```

Add `--format json` for machine-readable output (`out.v0.1`).

**Expected:** `security_state: NON_COMPLIANT`, with the compound control firing
on the WAF role — the Capital One shape:

```
CTL.IAM.FOOTHOLD.INTERNET.SENSITIVE.001   arn:aws:iam::111122223333:role/WAF-Role
CTL.S3.ENCRYPT.004                        arn:aws:s3:::cardholder-data
CTL.S3.OWNERSHIP.001                      arn:aws:s3:::cardholder-data
CTL.IAM.ROLE.INTENTTAG.001                arn:aws:iam::111122223333:role/WAF-Role
```

The finding that matters is `CTL.IAM.FOOTHOLD.INTERNET.SENSITIVE.001`: it fires
only when *internet-reachable compute* **and** *a role path to a sensitive
resource* co-exist. Single-resource checks can't see that join.

### The fixture

`fixtures/observations/2019-07-19T000000Z.json` models the three assets:

- an EC2 instance with IMDSv1 (`imds.v2_required: false`) and a public IP,
- the `WAF-Role` IAM role carrying the derived signals
  `identity.internet_facing: true` and `identity.reaches_sensitive: true`,
- a `cardholder-data` S3 bucket tagged `data-classification: pii`.

> The `internet_facing` / `reaches_sensitive` fields are **derived signals** a
> collector computes by running the graph reasoning in Demo B over the real IAM
> graph. The snapshot hand-sets them so you can see the catalog control consume
> them. Classification (`data-classification: pii`) is the precondition for
> "reaches a *sensitive* resource" to fire — an untagged bucket would be
> invisible to the chain.

---

## Demo B — the reachability proof behind the signal (Soufflé + Z3)

Shows **where `reaches_sensitive` comes from** — proven two independent ways
(Datalog reachability and an SMT existence check), which must agree.

Requires `souffle` and `z3` on `PATH`:

```bash
cd stave
PATH="$HOME/.local/bin:$PATH" bash examples/iam-foothold-internet-reach/run.sh
```

**Expected:**

```
vuln   souffle=PATH  z3=sat      internet-facing role -> sensitive resource   (FAIL)
fp     souffle=NONE  z3=unsat    same access but NOT internet-facing          (PASS)
fn     souffle=PATH  z3=sat      reached via a 2-hop assume chain             (FAIL)
```

Confirm it matches the committed expectation:

```bash
diff <(PATH="$HOME/.local/bin:$PATH" bash examples/iam-foothold-internet-reach/run.sh) \
     examples/iam-foothold-internet-reach/expected/output.txt && echo MATCHES
```

The **false-positive** row is the point: enforce IMDSv2 (or remove the public
reach) and the path collapses — `souffle=NONE / z3=unsat`, no finding. Stave
proves the chain is *broken*, not just that one box is checked. The cheapest cut
for the real breach was exactly this: enforce IMDSv2.

---

## How the two demos connect

| | Demo A (`stave apply`) | Demo B (reasoning spec) |
|---|---|---|
| Runs | the catalog control over a snapshot | Soufflé + Z3 over the IAM graph |
| Reads | derived `identity.reaches_sensitive` | raw assume/pass/access edges |
| Output | a finding (the verdict) | the proof the verdict rests on |

Demo A is what an operator runs; Demo B is the formal justification a collector
computes offline to populate the signal Demo A consumes.

## Notes / limitations of this demo

- The fixture uses illustrative IMDS field paths, so the standalone IMDSv2 /
  security-group **atomic** controls do not fire here — the **compound** foothold
  control (the actual Capital One detection) does. To exercise the atomic
  controls too, align the `compute.imds.*` / security-group fields to
  `docs/contract/compute.md`.
- Corpus reference: `incident:capital-one-2019` — see
  `docs/taxonomies/iam-compound.md` (Sub-family 1, Principal-policy-resource
  chains) and the reasoning spec at `examples/iam-foothold-internet-reach/`.
