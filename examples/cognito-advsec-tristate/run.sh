#!/usr/bin/env bash
set -uo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
# shellcheck source=../lib/cognito_demo.sh
source "$example_root/lib/cognito_demo.sh"
source "$example_root/lib/raw_flag.sh"
parse_raw_flag "$@"
set -- "${RAW_FLAG_ARGS[@]}"

cognito_demo_run \
    "Cognito Advanced Security tri-state — OFF / AUDIT / ENFORCED" \
    'CTL\.COGNITO\.ADVANCED\.SECURITY\.' \
    "off-mode:scenario:$script_dir/fixtures/off-mode/observations" \
    "audit-mode:scenario:$script_dir/fixtures/audit-mode/observations" \
    "enforced-mode:scenario:$script_dir/fixtures/enforced-mode/observations" \
    <<'EOF'
Cognito Advanced Security Features (ASF) has three modes:

  OFF       — risk metrics not collected, no enforcement
  AUDIT     — risk metrics collected, NO enforcement
              (visibility without protection)
  ENFORCED  — risk metrics collected AND adaptive auth enforces

The original CTL.COGNITO.ADVANCED.SECURITY.001 reads a rolled-up
boolean (advanced_security.enabled) and fires only on OFF mode.
That collapses AUDIT and ENFORCED into one bucket because both
have enabled=true. AUDIT is the "MFA is theatre" pattern applied
to ASF: the team sees risk scores in the console while the
application continues to authenticate suspicious sign-ins
without additional verification.

CTL.COGNITO.ADVANCED.SECURITY.AUDITONLY.001 (medium severity)
closes the gap by reading advanced_security.mode == "AUDIT"
directly. The two controls are additive:

  OFF      → ADVANCED.SECURITY.001 (high)         fires
  AUDIT    → ADVANCED.SECURITY.AUDITONLY.001 (med) fires
  ENFORCED → neither fires

The SIR projector now exports has_advanced_security_mode
alongside the existing has_advanced_security_enabled fact, so
future SMT queries can reason about the tri-state directly:

    (assert (or
      (has_advanced_security_mode pool "OFF")
      (has_advanced_security_mode pool "AUDIT")
    ))

In an AWS workflow: AUDIT mode is the most-commonly missed
configuration because the security team enables ASF, sees
metrics flowing, and assumes protection is active. The pricing
between AUDIT and ENFORCED is identical ($0.050 per MAU); only
OFF is free. Operators choose AUDIT during a "trial period"
that becomes permanent. This control flags those pools.
EOF
