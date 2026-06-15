# Demo conversation

A realistic exchange between a user, an AI agent, and the `stave` MCP
server. Tool outputs are abbreviated; the shapes match what the server
actually returns.

---

**User:** I have an AWS S3 snapshot in `./snapshots/s3/`. Can you check it for security issues?

**Agent** → `stave.verify`

```json
{ "observations_dir": "./snapshots/s3/", "format": "summary" }
```

**Result:**

```
Security State: NON_COMPLIANT
Posture Score:  82/100 (adequate)

Violations: 1 across 1 assets
  By severity:   critical 1
  SLA breaches:  0 (violations past their max-unsafe window)

Top findings by severity:
  1. [critical] CTL.S3.PUBLIC.001 — arn:aws:s3:::acme-customer-uploads: No Public S3 Bucket Read

Chain findings: 0

Evaluated: 2026-01-08T00:00:00Z | Snapshots: 2 | Assets: 1
```

**Agent:** Your bucket `acme-customer-uploads` is **NON_COMPLIANT** — one
critical finding: it allows public read. Posture score 82/100.

---

**User:** What exactly does `CTL.S3.PUBLIC.001` check?

**Agent** → `stave.catalog_explain`

```json
{ "control_id": "CTL.S3.PUBLIC.001" }
```

**Result:**

```json
{
  "id": "CTL.S3.PUBLIC.001",
  "name": "No Public S3 Bucket Read",
  "severity": "critical",
  "asset_types": ["aws_s3_bucket"],
  "predicate": "properties.storage.access.public_read eq true",
  "required_fields": ["properties.storage.access.public_read"],
  "frameworks": { "hipaa": "164.312(a)(1)", "pci_dss_v4.0": "7.2.1", "soc2": "CC6.1", "...": "..." },
  "remediation": "Bucket has public read access enabled via policy or ACL. Anyone on the internet can access objects in this bucket."
}
```

**Agent:** It fires when `storage.access.public_read` is `true`. It maps to
HIPAA 164.312(a)(1), PCI-DSS v4.0 7.2.1, SOC 2 CC6.1, and more. The fix is to
remove the public-read grant from the bucket policy/ACL.

---

**User:** Show me the other encryption-related controls I should know about.

**Agent** → `stave.search`

```json
{ "query": "S3 encryption at rest", "severity": "HIGH", "limit": 5 }
```

**Result:** ranked capability hits — control groups for S3 default
encryption, KMS key policy, and bucket-key enforcement, each with its member
control IDs and an example command.

**Agent:** Here are the high-severity encryption controls… (lists hits).
Want me to check your snapshot against any of these specifically, or look at
HIPAA compliance overall with `stave.compliance`?

---

## Notes

- `stave.verify`, `stave.gaps`, `stave.readiness`, `stave.compliance`, and
  `stave.diff` need snapshot paths and run only on the local binary.
- `stave.version`, `stave.search`, `stave.catalog_explain`, `stave.explain`,
  and `stave.suggest_fix` are catalog-query tools and also work in the hosted
  server.
