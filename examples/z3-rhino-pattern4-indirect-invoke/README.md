# z3-rhino-pattern4-indirect-invoke

Rhino Pattern 4 — Indirect Compute Invocation. Same template
as Pattern 1; different action disjunction. The principal
triggers compute execution **without direct invoke
permission** by writing to an event source that fans out to a
privileged Lambda or other compute primitive.

Rhino's named example: write to a DynamoDB table whose stream
triggers a Lambda. The this example prover generalised: SQS / SNS /
Kinesis publishers, S3 PutObject events, EventBridge rules,
IoT topic rules, SES receipt rules, CloudWatch alarms,
Cognito triggers — every event source AWS lets you wire to a
Lambda.

## Verdicts

| Fixture | Z3 | cvc5 | Witness |
|---|---|---|---|
| `rhino-vulnerable` | **sat** | `(timeout)` | `rhino-attacker` user with `cloudwatch:PutMetricAlarm` on `*` |
| `remediated` | **unsat** | unsat | n/a |

## Run

```bash
cd stave
make build
bash examples/z3-rhino-pattern4-indirect-invoke/run.sh
```

## See also

- `z3-rhino-pattern1-self-mutation/` — same template
- this example prover at
 `examples/iam-21-privesc-5-patterns/z3prove/patterns.go`
 — pattern4Methods registry
