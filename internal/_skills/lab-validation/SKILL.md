---
name: stave-lab-validation
description: Deploy a known-vulnerable Bishop Fox IAM lab, evaluate it with Stave, and confirm findings match the documented attack paths — trust via an independent oracle
triggers:
  - validate Stave
  - does Stave really work
  - verify against a known vulnerability
  - Bishop Fox iam-vulnerable
  - prove the tool detects escalation
requires:
  - a built stave binary (run stave-setup first)
  - an AWS SANDBOX account + profile (never production)
  - terraform (HashiCorp apt repo — see step 1)
---

# stave-lab-validation

## What this skill does
Deploys a known-vulnerable IAM configuration from Bishop Fox `iam-vulnerable`,
models a privesc user as a Stave observation, and confirms the finding matches
the documented attack path. The payoff is empirical trust: you watched Stave
match an independent expert oracle.

**Time:** ~30 minutes. **Cost:** $0 (IAM-only). **Requires a sandbox account.**

## Prerequisites
```
aws sts get-caller-identity --profile <your-sandbox-profile>   # must succeed
```
NEVER run this against production — the lab creates intentionally-vulnerable IAM users.

## Steps

### 1. Install Terraform (NOT in default apt)
```
terraform version || {
  wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
  sudo apt update && sudo apt install -y terraform
}
```
(Or download the binary from https://developer.hashicorp.com/terraform/install.)

### 2. Clone and deploy the lab (~30 IAM privesc paths, $0)
```
git clone https://github.com/BishopFox/iam-vulnerable.git
cd iam-vulnerable
export TF_VAR_aws_local_profile=<your-sandbox-profile>
terraform init && terraform apply    # type "yes"; ~2-3 min
aws iam list-users --profile <your-sandbox-profile> | jq '.Users | length'
```
Expect ~30 more users than before (names contain `privesc`).

### 3. Pick ONE privesc user and read its policy
Start simple. Example: `privesc4-CreateAccessKey-user`.
```
aws iam list-attached-user-policies --user-name privesc4-CreateAccessKey-user --profile <your-sandbox-profile>
# then aws iam get-policy-version on its policy → see the Action: iam:CreateAccessKey
```

### 4. Find the matching control and its exact field
```
./stave search "CreateAccessKey escalation"
# → CTL.IAM.ESCALATE.CREATEACCESSKEY.001
find controls -name '*CREATEACCESSKEY*' -exec grep -A4 unsafe_predicate {} \;
# field: properties.identity.escalation.create_access_key.present  (== true)
```
Read the control's `observation_fields` — those are the exact field names to populate.

### 5. Build the observation (use the EXACT field names; source must be deployed/planned/local)
```
mkdir -p ~/bf-obs
cat > ~/bf-obs/2026-01-01T000000Z.json << 'EOF'
{
  "schema_version": "obs.v0.1",
  "source": "deployed",
  "generated_by": { "source_type": "aws.cli" },
  "captured_at": "2026-01-01T00:00:00Z",
  "assets": [
    {
      "id": "arn:aws:iam::<ACCOUNT>:user/privesc4-CreateAccessKey-user",
      "type": "aws_iam_user",
      "vendor": "aws",
      "properties": {
        "identity": {
          "kind": "user",
          "escalation": {
            "create_access_key": {
              "present": true,
              "target_user_arn": "arn:aws:iam::<ACCOUNT>:user/some-admin",
              "permission_delta": ["iam:*"]
            }
          }
        }
      }
    }
  ]
}
EOF
```

### 6. Run Stave
```
./stave apply --observations ~/bf-obs/ --eval-time 2026-01-02T00:00:00Z
```
Expect **1 violation**: `CTL.IAM.ESCALATE.CREATEACCESSKEY.001` on that user.

### 7. Compare to the oracle
Bishop Fox documents privesc4 as "escalate via CreateAccessKey." Stave fired
`CTL.IAM.ESCALATE.CREATEACCESSKEY.001`. **Match → Stave detected the
documented escalation.** That is the trust step.

### 8. (Optional) Add more users
Model more privesc users (each policy → its control's `escalation.<x>.present`
field). Re-run; watch findings grow, each matching a Bishop Fox technique.

### 9. Tear down (always)
```
cd iam-vulnerable && terraform destroy   # type "yes"
aws iam list-users --profile <your-sandbox-profile> | jq -r '.Users[].UserName' | grep -ci privesc   # → 0
```

## Success
You verified Stave against an independent expert oracle; findings match the
documented attack paths. **Next:** `write-your-first-control`.
