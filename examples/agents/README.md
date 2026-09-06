# Stave Agent Templates

Two reference agents that collapse the distance between "I have Steampipe running"
and "I have my first Stave finding" from hours to minutes.

## Architecture

```
Steampipe          Agent 1              Agent 2              Stave
(cloud SQL)   →   Collector Agent  →   Transform Agent  →   stave apply
                  queries tables       validates + fixes     deterministic
                  outputs raw JSON     against schema        evaluation
                                       OODA self-correction
```

Both agents live in the **ingestion layer** — outside Stave's core. The deterministic
evaluation path is untouched. If an agent produces garbage, `stave lint` catches
it before Stave ever evaluates it.

## Agent 1: Steampipe Collector Agent (`steampipe_collector.py`)

Queries Steampipe tables and outputs raw JSON per asset. Does NOT transform to
Stave's observation format — that's Agent 2's job. This agent's only responsibility
is getting data out of Steampipe into structured JSON files.

```bash
python3 steampipe_collector.py --tables aws_s3_bucket,aws_iam_role --output ./raw/
```

## Agent 2: Stave Transform Agent (`stave_transform.py`)

Reads raw JSON (from Agent 1 or any source), transforms it to Stave's observation
contract, validates the output via `stave lint`, and self-corrects on failure.
Uses the observation schema and example transforms as context for an LLM to generate
the field mapping.

```bash
python3 stave_transform.py \
    --input ./raw/aws_s3_bucket.json \
    --asset-type aws_s3_bucket \
    --output ./observations/ \
    --validate   # runs stave lint in OODA loop
```

## The Contract Is the Interface

Both agents target Stave's published observation schema as a stable surface:

- `schemas/observation/v1/observation.schema.json` — base envelope
- `schemas/observation/v1/asset-types/*.schema.json` — 40 per-type property schemas

Any validator in any language can check the output:

```bash
stave lint --in output.obs.json --kind observation --strict
npx ajv validate -s observation.schema.json -d output.obs.json
check-jsonschema --schemafile observation.schema.json output.obs.json
```

## Quick Start

```bash
# 1. Ensure Steampipe + AWS plugin are installed
steampipe plugin install aws

# 2. Collect raw data from Steampipe
python3 steampipe_collector.py --tables aws_s3_bucket --output ./raw/

# 3. Transform to Stave observations (deterministic mode for known types)
python3 stave_transform.py \
    --input ./raw/aws_s3_bucket.json \
    --asset-type aws_s3_bucket \
    --output ./observations/ \
    --validate

# 4. Evaluate
stave apply --observations ./observations/

# 5. See gaps
stave gaps --observations ./observations/
```

## Modes

### Deterministic (default)

The transform agent ships built-in transforms for known asset types
(`aws_s3_bucket` today; others stub out with a clear "use --llm"
hint). Deterministic is the production path: no LLM, no network,
reproducible by construction. Fork the transform module to add
mappings for your organisation's Steampipe schema.

### LLM-assisted (`--llm`)

For types without a built-in transform, `--llm` mode sends the
target schema (path expectations) + the source column names to an
LLM and asks for a row-to-asset mapping. The agent applies the
returned mapping locally — your actual data values never leave the
machine. Requires `ANTHROPIC_API_KEY` (or another provider via
the small adapter in the script).

The transform is then validated; on failure, the validator's
error message is fed back to the LLM (OODA loop, three attempts).

## Forking Guide

These are starter templates, not production agents. Fork and adapt:

- Add your organization's Steampipe tables (custom resources, cross-cloud)
- Add custom pre-computed properties (delegation booleans, Access Advisor ratios)
- Wire into your CI/CD pipeline
- Replace the LLM transform with deterministic code once the mapping stabilizes

## Air-Gap Principle

No data leaves your machine. The collector queries your local Steampipe instance.
The transformer runs locally. The LLM call (if used) sends only the schema and
column names — never your actual data values. The observation files stay on disk.
Stave evaluates locally.

## Steampipe MCP Server (recommended for LLM-assisted mode)

For LLM-assisted transforms, the [Steampipe MCP server](https://github.com/turbot/steampipe-mcp)
gives the LLM direct SQL access to Steampipe. Instead of guessing mappings from
column names, the LLM can interactively:

1. `DESCRIBE aws_s3_bucket` — inspect the table schema
2. `SELECT * FROM aws_s3_bucket LIMIT 1` — see actual column shapes
3. Generate the transform with full context
4. Validate via `stave lint`
5. Self-correct on failure

Setup:

```bash
# Install the MCP server
npx steampipe-mcp

# Or configure in Claude Desktop / Claude Code:
#   ~/.config/claude-desktop/config.json
# Add to mcpServers:
#   "steampipe": { "command": "npx", "args": ["steampipe-mcp"] }
```

The deterministic path (built-in transforms, no LLM) uses subprocess and
doesn't need the MCP server. Use it for production pipelines and CI/CD.
