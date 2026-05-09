# compliance-evidence

Proof-to-evidence translator. Converts Stave's findings.json +
JSONL fact base into auditor-facing compliance evidence packets
mapped to regulatory controls. The auditor doesn't read SMT-LIB
output; they read this.

## What this answers

Companies spend $500K–$2M annually on SOC 2 / HIPAA / FedRAMP
audits. Auditors verify each regulatory control by reviewing
screenshots, configuration exports, and interview notes. Stave
already produces the proof — nine engines agreeing on the same
verdict over the same fact base. The proof is in solver output
format. This translator emits it in evidence-packet format.

| File | Audience | Content |
|---|---|---|
| `evidence-packet.md` | external auditor | per-control evidence chain (status, fired Stave controls, finding details, cross-reference) |
| `control-matrix.csv` | GRC / spreadsheet workflows | one row per regulatory control, ready for import into ServiceNow GRC, AuditBoard, etc. |
| `executive-summary.md` | board / CISO | compliance posture percentage + non-compliant control list + methodology paragraph |

## How the mapping is derived

Each Stave control already declares its compliance metadata:

```yaml
# controls/cognito/idpool/CTL.COGNITO.IDPOOL.UNAUTH.S3.001.yaml
compliance:
 cis_aws_v3.0: "1.16"
 soc2: "CC6.1, CC6.3, CC6.6"
 nist_800_53_r5: "AC-3, AC-4, AC-6, IA-2"
 pci_dss_v4.0: "7.1, 7.2"
 hipaa: "164.308(a)(4)(ii)(B), 164.312(a)(1)"
 iso_27001_2022: "A.5.15, A.8.2"
 ...
```

The generator scans the entire control catalog at run time,
splits each comma-separated metadata string, and builds an
inverted index: `regulatory_control_id → [stave_control_id, ...]`.
A new Stave control that declares `compliance.soc2: "CC6.1"`
**automatically** contributes to CC6.1's evidence stream — no
manual update to this directory is required.

The framework YAMLs in `frameworks/` only carry the regulatory
control titles + descriptions. They do **not** hand-curate
which Stave controls map to which regulatory ID — that would
duplicate the metadata that already lives in the catalog.

## Run

```bash
cd stave
make build
bash examples/compliance-evidence/run.sh
```

Pure stdlib + PyYAML. PyYAML lives in `.tools-venv` (the same
venv the other Python engines use); the runner activates it
and falls back to a `pip install pyyaml` only when the venv
doesn't already have it.

## Live verdict matrix (golden in `expected/`)

| Fixture | Framework | Compliant | Non-compliant | Not assessed |
|---|---|---:|---:|---:|
| Cognito writeup | SOC 2 | 3 | 2 | 0 |
| Cognito remediated | SOC 2 | 5 | 0 | 0 |
| Cognito writeup | HIPAA | 5 | 1 | 0 |
| Cognito remediated | HIPAA | 6 | 0 | 0 |

The deltas are the value:

- **SOC 2 writeup → remediated**: CC6.1 (Access Controls) and
 CC6.3 (Least Privilege) flip from FAIL to PASS as the
 Cognito gates close. CC6.6 (Boundary) stays compliant —
 the writeup-config's bucket policy was already private.

- **HIPAA writeup → remediated**: 164.312(d) (Person /
 Entity Authentication) was the single FAIL because
 `CTL.COGNITO.MFA.001` fired — the user pool didn't require
 MFA. Remediation enables MFA, and the same control no
 longer fires.

The cross-framework view is informative: the *same*
configuration yields different non-compliant counts under
different frameworks because each framework cares about
different regulatory IDs. SOC 2 cares about CC6.3 (which
catches `IAM.ROLE.INTENTTAG`); HIPAA does not. HIPAA cares
about 164.312(d) (which catches `COGNITO.MFA`); SOC 2 maps
that to CC6.1 (already failing). Same proof, two formats.

## Adding a regulatory framework

1. Drop a new YAML at `frameworks/<basename>.yaml` with
 `framework`, `version`, `metadata_field`, and a `controls:`
 map of regulatory IDs → titles + descriptions +
 cross-references.
2. The `metadata_field` value is the key under each Stave
 control's `compliance:` block (e.g. `soc2`, `hipaa`,
 `nist_800_53_r5`, `pci_dss_v4.0`).
3. Re-run `bash run.sh` — the inverted index rebuilds
 automatically.

For the supplied frameworks, mappings depend purely on what
Stave controls declare. To improve coverage:

- Add the regulatory metadata to controls that lack it (the
 `compliance:` block is freely extensible).
- Add new controls under `stave/controls/...` — they enter
 the index at the next run.

## What this is not

- **Not a replacement for the auditor.** The evidence
 *supports* the audit — it provides the reasoning chain the
 auditor would otherwise verify manually. The auditor still
 signs off, still asks questions, still validates that the
 evidence presented is consistent with the actual deployment.

- **Not a complete framework mapping.** The shipped YAMLs cover
 five SOC 2 controls and six HIPAA controls — enough to
 demonstrate the proof-to-evidence translation, not enough to
 cover an entire framework. Expanding is one entry-per-control
 in YAML; the inverted index handles the rest.

- **Not a substitute for the engine examples.** This
 generator consumes the same `findings.json` and `facts.jsonl`
 the other engines do. It does not run new analyses; it
 *translates* the existing analysis into a regulatory-control
 vocabulary.

- **Not a fact-of-record system.** Treat the output as audit
 *evidence*, not audit *truth*. The CEL findings, SMT proofs,
 and engine consensus are the truth; this translator chooses
 one regulatory-control vocabulary to render them in.
