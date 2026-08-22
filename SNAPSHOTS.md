## Snapshots

Stave evaluates local JSON files (`obs.v0.1`), not live APIs.
Capture once, evaluate anywhere offline, deterministic and auditable.

| Topic | What it covers |
|-------|----------------|
| [Snapshot Model](docs/explanation/snapshot-model.md) | Why local files instead of live queries — the air-gap constraint |
| [Import Snapshots](docs/getting-started/import-snapshots.md) | Three ways to produce `obs.v0.1` JSON: aws CLI + jq, Steampipe, bundled collector |
| [Capture Guide](docs/transform/capture.md) | Running the bundled collector (read-only, zero install) |
| [Collector IAM Policy](docs/trust/collector-policy.md) | Minimum IAM role — every action is Get, List, or Describe |
| [Schema](docs/snapshot.schema.json) | JSON Schema for the observation format |
| [Snapshot Your Account](internal/_skills/snapshot-your-account/SKILL.md) | Guided skill: capture your own AWS account (30 min) |
