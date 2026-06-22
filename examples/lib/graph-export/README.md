# Library example: `ExportGraph` — the cross-service relationship view

A small Go program that uses Stave's library API
(`github.com/sufield/stave/pkg/stave`) to project an `Assessment` into a
**graph export**: the assets an assessment touched, the findings and
chains that hang off them, and the edges between. It also shows the
optional `WithSIRDocument` enrichment that adds transitive IAM role
chains and per-asset lifecycle.

This is the worked counterpart to the `pkg/stave.ExportGraph` API — the
"what reaches what" half of Stave's export surface (the policy half is
`ExportPolicies`).

## Run it

```bash
cd stave
go run -tags graphexample ./examples/lib/graph-export
```

The `graphexample` build tag keeps the program out of the normal module
build (`go build ./...` skips it), exactly like the `z3-public-exposure`
example. You only pay for it when you ask for it.

## What `ExportGraph` does

```go
func ExportGraph(assessment *stave.Assessment, opts ...stave.GraphOption) *stave.GraphExport
```

Given an `*Assessment` (from `stave.Apply`, `stave.LoadAssessment`, or
`stave.FromReportAssessment`), it returns a `*GraphExport` with five
slices:

| Field | What it carries |
|---|---|
| `Assets` | One deduplicated `AssetNode` per `(AssetID, AssetType)` the findings reference. `HasFinding` flags exposed assets. No snapshot required — derived from the findings alone. |
| `Edges` | `finding_about` edges (finding → its asset) and `chain_member` edges (chain → member finding). Sorted for stable diffs. |
| `Findings` | One `FindingNode` per finding — the subset SMT solvers and visualisers reason over (id, control, asset, severity, exposure score, chain membership, optional lifecycle). |
| `Chains` | One `ChainNode` per compound chain finding, with its member finding ids and failing controls. |
| `TransitiveReachability` | Flattened multi-hop `sts:AssumeRole` paths. **Empty unless** you pass `WithSIRDocument` (see below). |

`ExportGraph(nil)` returns `nil`, so it composes through optional
pipelines without nil-guarding.

### Basic export

```go
a := stave.LoadAssessment(ctx, "assessment.json") // or stave.Apply(...)
graph := stave.ExportGraph(a)
json.NewEncoder(os.Stdout).Encode(graph)
```

Output (trimmed):

```json
{
  "Assets": [
    { "ID": "arn:aws:s3:::data-bucket", "Type": "aws_s3_bucket", "HasFinding": true }
  ],
  "Edges": [
    { "FromAssetID": "data_exfil_path", "ToAssetID": "fid-public-acl", "Relationship": "chain_member" },
    { "FromAssetID": "fid-public-acl",  "ToAssetID": "arn:aws:s3:::data-bucket", "Relationship": "finding_about" }
  ],
  "Findings": [
    { "FindingID": "fid-public-acl", "ControlID": "CTL.S3.ACCESS.001", "Severity": "high",
      "ExposureScore": 7.5, "IsChainMember": true, "Lifecycle": null }
  ],
  "Chains": [
    { "ChainID": "data_exfil_path", "Severity": "critical", "CompoundScore": 9.2,
      "ControlsFailing": ["CTL.S3.ACCESS.001"], "Members": ["fid-public-acl"] }
  ],
  "TransitiveReachability": null
}
```

## Enriching with a SIR document

```go
graph := stave.ExportGraph(a, stave.WithSIRDocument(doc))
```

`WithSIRDocument` hydrates two things the `Assessment` alone can't supply,
reading them straight from a `sir.Document` (no recomputation):

- **`AssetNode.Lifecycle`** — the asset's existence envelope
  (`provisioned` / `decommissioned` / `first_seen` / `last_seen`).
- **`GraphExport.TransitiveReachability`** — one entry per role-assumption
  path, with the hop sequence, hop types, a `cross_account_hop` flag, the
  final role's privilege level, and why the resolver stopped.

```json
"TransitiveReachability": [
  {
    "from_principal": "arn:aws:iam::111122223333:user/ci-deployer",
    "final_role":     "arn:aws:iam::444455556666:role/prod-admin",
    "hops":           ["arn:aws:iam::444455556666:role/prod-admin"],
    "hop_types":      ["assume_role"],
    "cross_account_hop": true,
    "transitive_level":  "admin",
    "termination_reason": "normal"
  }
]
```

`WithSIRDocument(nil)` is a no-op, and the option is idempotent — the same
`(assessment, document)` input produces byte-identical output across runs.

> **Where the SIR document comes from.** `sir.Document` lives in
> `internal/core/sir`, so only code *inside* the Stave module (like this
> example) can construct one directly — which is why this example lives
> under `stave/examples/`. In a real pipeline the document is the one an
> `Apply` run already built for fact-id correlation; `WithSIRDocument`
> exists so consumers surface those facts through the public graph API
> instead of rebuilding the transitive closure themselves.

## Downstream consumers

- **Graph visualisers** (Neo4j and friends) consume `Assets` + `Edges`
  directly — concatenate with `ExportPolicies`' `AssetRelationships` for
  the full edge set.
- **SMT / Z3 reachability** consumes `Findings` + `Chains` as conjectures
  to discharge against the asset graph, and reads
  `TransitiveReachability` as the `can_assume(from, to)` edges without
  rebuilding the closure.
- **SLA / dwell-time queries** read `FindingNode.Lifecycle.UnsafeDurationHours`
  — the same value `--max-unsafe` compares against on the CLI.

## Files

- `main.go` — the runnable program (basic export + `WithSIRDocument`).
- `README.md` — this file.
