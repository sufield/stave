# Chain Discovery — Live AWS Validation

Run the discovery engine against a real AWS account to produce
access-graph edges the lab fixtures don't carry.

**Time:** ~10 minutes. **Cost:** $0 (read-only API calls + short-lived test roles).

## Prerequisites

```bash
# Verify tools
stave version          # Stave binary built
souffle --version      # Soufflé 2.5+
aws sts get-caller-identity   # AWS credentials active
jq --version           # jq installed

# Build stave if needed
cd stave && make build
```

## Step 1: Create Test Roles (3 minutes)

Create a 3-hop assume chain with known permissions so the
discovery engine has edges to find.

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Role C — the "admin" target at the end of the chain.
aws iam create-role \
  --role-name stave-discovery-admin \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::'$ACCOUNT_ID':role/stave-discovery-operator"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy \
  --role-name stave-discovery-admin \
  --policy-name admin-policy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "iam:*",
      "Resource": "*"
    }]
  }'

# Role B — mid-chain, can assume Role C.
aws iam create-role \
  --role-name stave-discovery-operator \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::'$ACCOUNT_ID':role/stave-discovery-dev"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy \
  --role-name stave-discovery-operator \
  --policy-name operator-policy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "arn:aws:iam::'$ACCOUNT_ID':role/stave-discovery-admin"
      },
      {
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:PutObject"],
        "Resource": "arn:aws:s3:::*"
      }
    ]
  }'

# Role A — entry point, can assume Role B.
aws iam create-role \
  --role-name stave-discovery-dev \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy \
  --role-name stave-discovery-dev \
  --policy-name dev-policy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::'$ACCOUNT_ID':role/stave-discovery-operator"
    }]
  }'
```

**Expected graph:**
```
dev (lambda-trusted) → operator → admin (iam:*)
                         ↓
                     s3:PutObject on *
```

## Step 2: Capture Observations (2 minutes)

Build Stave-formatted observation snapshots from the live roles.

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
OBS_DIR=/tmp/stave-live-discovery/observations
mkdir -p "$OBS_DIR"

capture_snapshot() {
  local TIMESTAMP=$1
  local OUT="$OBS_DIR/${TIMESTAMP}.json"

  # Fetch role data
  ROLES=""
  for ROLE_NAME in stave-discovery-dev stave-discovery-operator stave-discovery-admin; do
    ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

    # Get role metadata
    ROLE_DATA=$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role' 2>/dev/null)
    TRUST_POLICY=$(echo "$ROLE_DATA" | jq -c '.AssumeRolePolicyDocument')

    # Get inline policy
    POLICY_DOC=$(aws iam get-role-policy \
      --role-name "$ROLE_NAME" \
      --policy-name "$(echo $ROLE_NAME | sed 's/stave-discovery-//')-policy" \
      --query 'PolicyDocument' 2>/dev/null | jq -c '.')

    # Determine properties
    KIND="role"
    HAS_ADMIN=$(echo "$POLICY_DOC" | jq 'any(.Statement[]; .Action == "iam:*" or .Action == "*")')
    SERVICE_WILDCARDS=$(echo "$POLICY_DOC" | jq '[.Statement[].Action] | flatten | map(select(endswith(":*"))) | length')

    # Build asset JSON
    ASSET=$(jq -n \
      --arg id "$ROLE_ARN" \
      --arg name "$ROLE_NAME" \
      --arg kind "$KIND" \
      --arg trust_json "$TRUST_POLICY" \
      --arg policy_json "$POLICY_DOC" \
      --argjson has_admin "$HAS_ADMIN" \
      --argjson svc_wildcards "$SERVICE_WILDCARDS" \
      '{
        id: $id,
        type: "aws_iam_role",
        vendor: "aws",
        properties: {
          identity: {
            kind: $kind,
            name: $name,
            trust_policy_json: $trust_json,
            policies_json: $policy_json,
            policies: {
              has_admin_access: $has_admin,
              service_wildcards_granted: $svc_wildcards,
              has_inline_policies: true
            },
            trust_policy: {
              has_cross_account_trust: false
            }
          }
        }
      }')

    if [ -n "$ROLES" ]; then ROLES="${ROLES},"; fi
    ROLES="${ROLES}${ASSET}"
  done

  # Write snapshot
  jq -n \
    --arg ts "$TIMESTAMP" \
    --argjson assets "[$ROLES]" \
    '{
      schema_version: "obs.v0.1",
      captured_at: $ts,
      source: "deployed",
      assets: $assets
    }' > "$OUT"

  echo "  wrote $OUT ($(jq '.assets | length' "$OUT") assets)"
}

echo "Capturing snapshot 1..."
capture_snapshot "2026-01-01T000000Z"

echo "Capturing snapshot 2..."
capture_snapshot "2026-01-11T000000Z"
```

## Step 3: Run Discovery (1 minute)

```bash
cd stave

# Text report
make chain-discover ARGS="-snapshot /tmp/stave-live-discovery/observations -now 2026-01-11T00:00:00Z"

# JSON output
make chain-discover ARGS="-snapshot /tmp/stave-live-discovery/observations -now 2026-01-11T00:00:00Z -json"
```

### Expected Results

```
═══════════════════════════════════════════════
CHAIN DISCOVERY
═══════════════════════════════════════════════

DATALOG EVALUATION:
  privesc_path:              ___    ← PLACEHOLDER: expect 3-6 (1+2+3 hop prefixes)
  access_path:               ___    ← PLACEHOLDER: expect >0 (s3 grants via assume chains)
  escalation_path:           ___    ← PLACEHOLDER: expect 1-3 (dev→operator→admin)
  exfil_path:                ___    ← PLACEHOLDER: expect 1+ (operator has s3:PutObject on *)
  external_reach:            ___    ← PLACEHOLDER: expect 0 (no cross-account edges)
  confused_deputy_path:      ___    ← PLACEHOLDER: expect 0-1 (lambda.amazonaws.com trust)
  path_condition:            ___    ← PLACEHOLDER: expect 0 (no conditions on trust policies)

CLASSIFICATION:  ___ total paths
  escalation:                ___
  exfiltration:              ___

DEDUPLICATION:  ___ novel, ___ confirmed
```

**What to look for:**

- `privesc_path > 0` confirms the assume chain is visible.
- `escalation_path > 0` confirms the engine finds dev → admin via iam:*.
- `exfil_path > 0` confirms the engine finds the s3:PutObject wildcard path.
- `novel > 0` means the engine found chains not in the 622 YAML definitions.
- If ALL zeros: the observation snapshots are missing `trust_policy_json`
  or `policies_json` — the SIR projectors need these raw JSON strings
  to emit `can_assume` and `has_action`/`has_resource` edges.

## Step 4: Cleanup (1 minute)

```bash
for ROLE_NAME in stave-discovery-dev stave-discovery-operator stave-discovery-admin; do
  POLICY_NAME="$(echo $ROLE_NAME | sed 's/stave-discovery-//')-policy"
  aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY_NAME" 2>/dev/null
  aws iam delete-role --role-name "$ROLE_NAME" 2>/dev/null
  echo "deleted $ROLE_NAME"
done

rm -rf /tmp/stave-live-discovery
```

## Troubleshooting

**All zeros despite roles existing:**

Check the SIR facts export directly:

```bash
./stave export-sir \
  --controls controls \
  --observations /tmp/stave-live-discovery/observations \
  --eval-time 2026-01-11T00:00:00Z \
  --format jsonl | jq -r '.predicate' | sort | uniq -c | sort -rn | head -20
```

Look for `can_assume`, `has_action`, `has_resource`, `trusts_service`.
If missing, the observation JSON is missing the fields the SIR projectors
read. Compare against a working fixture:

```bash
# Reference: what a working fixture looks like
cat examples/iam-multi-hop-trust/fixtures/vulnerable/observations/2026-01-01T000000Z.json | jq '.assets[0].properties.identity | keys'
```

The critical fields are:
- `trust_policy_json` — raw JSON string of the trust policy (produces `can_assume`)
- `policies_json` — raw JSON string of the identity policy (produces `has_action`, `has_resource`)

**Soufflé not found:**

```bash
# Install from GitHub release
curl -fsSL https://github.com/souffle-lang/souffle/releases/download/2.5/x86_64-ubuntu-2404-souffle-2.5-Linux.deb -o /tmp/s.deb
dpkg-deb -x /tmp/s.deb /tmp/sx
cp /tmp/sx/usr/bin/souffle* ~/.local/bin/
export PATH=$HOME/.local/bin:$PATH
```
