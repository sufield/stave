# Soufflé Reasoning Engine

Datalog programs that detect compound attack paths across the AWS
access graph. Stave's CEL predicates evaluate individual controls;
these Soufflé programs reason over relationships between principals,
roles, resources, and permissions to find multi-hop chains a single
control cannot see.

## Programs

| Directory | Program | What It Detects |
|-----------|---------|-----------------|
| `iam/` | `schema.dl` | G0 base-fact schema — input relations from SIR-facts, derived views (principal/resource/trust), sanity counts |
| `iam/` | `rules.dl` | G1 transitive closure + scope-aware effective access — role-assumption chains, scoped reachable actions/resources (account-level joins), unauthorized access, CIA violation queries (G4 Confidentiality, G5 Integrity) |
| `iam/` | `action_classes.dl` | Read/write action classification for CIA queries — covers S3, DynamoDB, KMS, Secrets Manager, RDS, Redshift, Glue |
| `discovery/` | `discovery.dl` | Path-tracking reachability — emits full hop sequences with security classification (escalation, exfiltration, external, confused deputy) |
| `discovery/` | `bucket_hijack.dl` | Bucket hijacking chains — dangling destinations, delete-to-exfiltrate, security telemetry hijack, cross-account destinations |

## Pipeline

```
Observation snapshots
  → stave export-sir --format jsonl
  → extract.go (per-predicate TSV .facts files)
  → souffle -F facts/ -D out/ program.dl
  → emit_findings.go / report.go (CompoundFindings back into Stave)
```

## Running

```bash
# Extract facts from observations
go run ./reasoning/souffle/iam/extract.go \
    -snapshot ./observations -out ./facts

# IAM access graph (transitive closure + CIA queries)
souffle reasoning/souffle/iam/rules.dl -F ./facts -D ./out

# Chain discovery (path-tracking + classification)
souffle reasoning/souffle/discovery/discovery.dl \
    -F ./facts -D ./out -I reasoning/souffle/iam/

# Bucket hijack chains
souffle reasoning/souffle/discovery/bucket_hijack.dl \
    -F ./facts -D ./out -I reasoning/souffle/iam/
```

## Go Harnesses

| File | Purpose |
|------|---------|
| `iam/extract.go` | Extracts SIR-facts from Stave snapshots or JSONL into per-predicate `.facts` TSV files |
| `iam/validate.go` | Cross-validates Datalog findings against CEL compound predicates |
| `iam/emit_findings.go` | Converts Soufflé output tuples into Stave CompoundFindings |
| `discovery/main.go` | Orchestrates discovery pipeline: extract → Soufflé → classify → report |
| `discovery/verify.go` | Validates discovery results against known fixtures |
| `discovery/dedup.go` | Deduplicates discovered chains against the existing YAML chain catalog |
| `discovery/report.go` | Renders discovery results as text or JSON reports |

## Relation Hierarchy

```
Input (SIR-facts)          Derived (Datalog)
─────────────────          ─────────────────
has_type              ──→  principal_type, resource
has_action            ──→  reachable_action, scoped_reachable_action
has_resource          ──→  reachable_resource, scoped_reachable_resource
has_scope             ──→  scoped_reachable_action, scoped_reachable_resource
can_assume            ──→  transitive_assume
has_deny_action       ──→  reachable_deny_action
                      ──→  effective_allow (scope-constrained) / effective_deny
                      ──→  effective_permission
                      ──→  effective_access
authorized            ──→  unauthorized_access
sensitivity           ──→  violation_c (confidentiality)
                      ──→  violation_i (integrity)
                      ──→  privesc_path (discovery)
                      ──→  escalation_path, exfil_path
```

## Known Limitations

Documented in `schema.dl` and `rules.dl` headers:

1. **No group membership** — `aws_iam_group` not in the observation contract
2. **Intra-account Cartesian** — effective access within a single identity context is still an over-approximation (more permissive than per-statement reasoning); cross-account Cartesian eliminated by scope-aware joins
3. **Partial condition support** — condition-aware trust queries need extended SIR-facts emission
4. **ARN matching** — exact, universal `*`, and trailing `*` only; no mid-pattern wildcards

See `iam/README.md` for the full G0–G5 phase context.
