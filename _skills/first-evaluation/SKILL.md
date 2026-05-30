---
name: stave-first-evaluation
description: Run Stave against a tiny example observation and read your first findings — no AWS account required
triggers:
  - first findings
  - see Stave work
  - what does a finding look like
  - try Stave without AWS
  - stave apply example
requires:
  - a built stave binary (run the stave-setup skill first)
---

# stave-first-evaluation

## What this skill does
Produces real findings from a one-asset example observation so you see the
output shape — finding, evidence, reasoning, remediation. **No AWS needed.**

**Time:** ~10 minutes.

## Steps

### 1. Confirm Stave is built
```
./stave version    # if this fails, run the stave-setup skill
```

### 2. Create a minimal observation
There is no bundled `examples/observations/` dir, so create one. NOTE the two
fields that must be exact or `stave apply` exits 2 (input error):
- `source` MUST be one of `deployed` | `planned` | `local` (NOT "example").
- `schema_version` MUST be `obs.v0.1`.

```
mkdir -p /tmp/stave-demo/obs
cat > /tmp/stave-demo/obs/2026-01-01T000000Z.json << 'EOF'
{
  "schema_version": "obs.v0.1",
  "source": "deployed",
  "generated_by": { "source_type": "manual" },
  "captured_at": "2026-01-01T00:00:00Z",
  "assets": [
    {
      "id": "arn:aws:iam::111111111111:user/demo-user",
      "type": "aws_iam_user",
      "vendor": "aws",
      "properties": {
        "identity": {
          "kind": "user",
          "name": "demo-user",
          "arn": "arn:aws:iam::111111111111:user/demo-user",
          "policies": { "has_admin_access": true, "service_wildcards_granted": true }
        }
      }
    }
  ]
}
EOF
jq . /tmp/stave-demo/obs/*.json > /dev/null && echo "valid JSON"
```

### 3. Run Stave (use --now for deterministic output)
```
./stave apply --observations /tmp/stave-demo/obs/ --now 2026-01-02T00:00:00Z
```
**Expected: 2 violations** on `demo-user`:
- `CTL.IAM.POLICY.ADMIN.001` (the user has admin access)
- `CTL.IAM.CROSSCLOUD.ADMIN.001`

Exit code **3** = violations found (0 = clean, 2 = input error, 3 = violations, 4 = internal).

### 4. Read the output
Each finding shows: the control + asset, evidence (when the violation began),
the root-cause property that triggered it, and remediation guidance.

### 5. Try the machine-readable formats
```
./stave apply --observations /tmp/stave-demo/obs/ --now 2026-01-02T00:00:00Z --format json
./stave apply --observations /tmp/stave-demo/obs/ --now 2026-01-02T00:00:00Z --format sarif
```
JSON follows the stable `out.v0.1` schema; SARIF carries a `runs` array for
code-scanning tools.

## Success
You've produced findings from an observation and understand the output + exit
codes. **Next:** `lab-validation` (needs a sandbox AWS account).
