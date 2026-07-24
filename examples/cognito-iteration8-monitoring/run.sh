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
    "Cognito Iteration 8 — 10 monitoring / alarm controls" \
    'CTL\.COGNITO\.(ALARM|METRICS)' \
    "writeup-config:before:$script_dir/fixtures/writeup-config/observations" \
    "remediated-config:after:$script_dir/fixtures/remediated-config/observations" \
    <<'EOF'
Iteration 8 covers CloudWatch alarms and metrics for
critical Cognito management and authentication events.
Introduces the aws_cognito_account asset type — an
account-region-scoped aggregation rather than a per-pool
state. No compound chain — each missing alarm is
independently actionable.

Before — writeup-config: an aws_cognito_account asset where
none of the 9 critical-event alarms are configured and login
metrics aren't tracked. 10 individual findings.

After — remediated-config: every alarm + metric configured.
0 findings.

Architecture observation: this is the
account-aggregation pattern. The collector queries
aws_cloudwatch_log_metric_filter, joins to
aws_cloudwatch_alarm, and joins to aws_cloudtrail_trail to
confirm the trail captures the management events; it then
stamps the joined-up boolean on the account asset. Stave
fires one finding per missing alarm at the account level
rather than one per user pool — right shape for monitoring
controls because "no alarm for AdminCreateUser" is a
property of the account, not any individual pool.

In an AWS workflow: monitoring controls are the slowest to
discover because the absence of a signal is itself silent.
Iteration 8 makes the absence visible at configuration time.
A future "Cognito monitoring blindspot" compound could
compose these with CloudTrail-side findings via scope_field
on account_id; today each finding stands alone.
EOF
