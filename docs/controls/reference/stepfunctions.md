# Control Reference — STEPFUNCTIONS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.STEPFUNCTIONS.ACTIVITY.ZOMBIE.001

**Step Functions Activity Worker Replaced By Integration But Not Decommissioned**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-8; iso_27001_2022: A.5.9; nist_800_53_r5: CM-8; soc2: CC8.1;

Step Functions Activity (legacy worker pattern, polled via GetActivityTask) was replaced by a managed integration but the Activity itself was never deleted from the state machine's environment. Workers may still be polling; activity ARN occupies the namespace; CloudTrail still logs ListActivities.

**Remediation:** DeleteActivity on the orphan ARN. Audit via ListActivities periodically and cross-check against in-use Activity ARNs in current state-machine definitions.

---

### CTL.STEPFUNCTIONS.ALARM.EXEC.FAILED.001

**Step Functions ExecutionsFailed Has No CloudWatch Alarm**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12, SI-4; soc2: CC7.2, A1.1;

No CloudWatch alarm on the `ExecutionsFailed` metric. Failed executions accumulate without paging on-call; only customer impact (or daily review) surfaces them. The metric is the most direct workflow-health signal.

**Remediation:** Create alarm: ExecutionsFailed > 0 for 1 datapoint, page on-call. For high-volume workflows, alarm on rate (>5%) instead of raw count.

---

### CTL.STEPFUNCTIONS.ALARM.EXEC.THROTTLED.001

**Step Functions ExecutionThrottled Has No CloudWatch Alarm**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12, SI-4; soc2: CC7.2, A1.1;

No CloudWatch alarm on `ExecutionThrottled`. When the workflow hits Step Functions rate limits (10K/sec StartExecution per region, account-level concurrent execution quota), events are dropped silently. Without an alarm, the workflow appears to "process less data than expected" without traceable cause.

**Remediation:** Alarm: ExecutionThrottled > 0 sustained 5 minutes (warn). Investigate via Service Quotas; request limit increase if needed.

---

### CTL.STEPFUNCTIONS.ALARM.EXEC.TIME.SLO.001

**Step Functions ExecutionTime Has No SLO Alarm**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12; soc2: CC7.2, A1.1;

No CloudWatch alarm on `ExecutionTime` bounded by an SLO (e.g., p99 < 60s). Long-running stuck executions accumulate invisibly; downstream consumers wait on results that arrive far past expected. Particularly important for synchronous Express patterns where the caller has its own timeout.

**Remediation:** Alarm: ExecutionTime p99 > <SLO> sustained 15min. Set SLO based on workflow's documented SLA.

---

### CTL.STEPFUNCTIONS.ALARM.SCHEDULE.TIME.001

**Step Functions Activity / Lambda Schedule Time Alarms Missing**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12; soc2: CC7.2, A1.1;

No CloudWatch alarms on `ActivityScheduleTime` or `LambdaFunctionScheduleTime`. These metrics capture time-to-schedule (queue wait) on worker queues — high values mean workers are saturated. Without alarms, ingest queues back up invisibly until customer impact.

**Remediation:** Alarm: ActivityScheduleTime p99 > 30s and LambdaFunctionScheduleTime p99 > 5s (workload-tunable). High values indicate worker / Lambda concurrency saturation.

---

### CTL.STEPFUNCTIONS.ALIAS.LATEST.001

**Step Functions Default Alias Points To $LATEST Instead Of Versioned Target**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.8.32; nist_800_53_r5: CM-3; soc2: CC8.1;

Step Functions default alias points to `$LATEST` rather than a versioned alias. Each deploy moves $LATEST forward immediately; callers using the unqualified ARN hit the new code without canary or rollback path.

**Remediation:** Re-point default alias to a versioned target updated atomically by the deploy pipeline (e.g., `prod` alias pointing at a specific version number).

---

### CTL.STEPFUNCTIONS.ALIAS.NOWEIGHTED.001

**Step Functions Aliases Don't Use Weighted Routing For Canary Deploys**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.8.32; nist_800_53_r5: CM-3; soc2: CC8.1, A1.1;

Step Functions aliases route 100% of StartExecution calls to a single version. Deploys are all-or-nothing; canary deploys (route 1% to new version, watch alarms, then ramp) impossible. Production deploys carry full risk on every change.

**Remediation:** Configure weighted RoutingConfiguration when deploying new versions; e.g., new version 5%, prior version 95%, ramp over hours while watching ExecutionsFailed alarm.

---

### CTL.STEPFUNCTIONS.ALIAS.ROLE.UNVERSIONED.001

**Step Functions Alias-Based StartExec But IAM Role References Unversioned ARN**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15; nist_800_53_r5: AC-6; soc2: CC6.1, CC8.1;

Step Functions caller role grants `states:StartExecution` on the unversioned state-machine ARN, but the workflow uses versioned aliases. Alias-based callers work, but the IAM grant is broader than necessary — any new alias / version is automatically reachable. Defeats the purpose of canary deploys for IAM-tier scoping.

**Remediation:** Pin the role's Resource to the alias ARN (or specific version ARN). Update pipeline to pass through alias on deploy.

---

### CTL.STEPFUNCTIONS.APIGW.UNVERSIONED.ARN.001

**Step Functions API Gateway Integration Targets Unversioned State Machine ARN**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.8.32; nist_800_53_r5: CM-3; soc2: CC8.1, A1.2;

API Gateway integration with Step Functions uses the unversioned state machine ARN. Same failure mode as EventBridge unversioned: any new alias / version is exposed; canary deploys have no effect on the API GW caller path.

**Remediation:** Update integration request URI to use alias ARN. Pair API Gateway stage with state-machine alias for environment- aligned routing.

---

### CTL.STEPFUNCTIONS.ASL.CATCH.MISSING.001

**Step Functions Task State Lacks Catch Clause On Failure-Prone Downstream**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4, A1.2;

Step Functions ASL definition has a `Task` state with no `Catch` clause invoking a downstream service that can fail (Lambda, DDB, API call). Without `Catch`, any error propagates as workflow termination — no cleanup, no compensation, no operator notification. Production workflows need explicit error paths.

**Remediation:** Add Catch with explicit error name and Next state for the failure path:
  "Catch": [{
    "ErrorEquals": ["States.TaskFailed"],
    "Next": "HandleError",
    "ResultPath": "$.error"
  }]

---

### CTL.STEPFUNCTIONS.ASL.CATCH.STATES.ALL.001

**Step Functions Catch Matches States.ALL Routing All Errors To Same Path**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4;

ASL `Catch` clause matches `States.ALL` and routes every error type to the same handler. States.ALL conflates retryable transient errors with permanent ones (validation, permissions, malformed input) — the handler cannot distinguish "retry this" from "page on-call." Different error classes need different paths.

**Remediation:** Replace with multiple Catch clauses keyed on specific ErrorEquals values (States.TaskFailed, States.Timeout, Lambda.Unknown, custom error names from the workflow).

---

### CTL.STEPFUNCTIONS.ASL.CHOICE.NODEFAULT.001

**Step Functions Choice State Lacks Default Clause**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4;

ASL `Choice` state has no `Default` clause. When input doesn't match any `Choices` rule, Step Functions terminates the execution with `States.NoChoiceMatched`. Production workflows should always have an explicit Default for unexpected input — even if it routes to a Fail state with a captured error.

**Remediation:** Add Default clause routing to a Fail state with explicit error / cause, or to a known-safe handling path.

---

### CTL.STEPFUNCTIONS.ASL.DM.CHILD.IAM.INHERIT.001

**Step Functions Distributed Map Child Executions Inherit Parent's Broad IAM**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6; soc2: CC6.1, CC6.3;

Distributed Map's child executions inherit the parent state machine's IAM execution role. If the parent role is broadly scoped (already a defect from SF-2), every child execution multiplies the blast radius — thousands of concurrent processes operating with the same broad permissions, any of which can be compromised by a malicious input record.

**Remediation:** Define a separate child execution role for Distributed Map iterations. Scope the child role to only the actions a single iteration needs.

---

### CTL.STEPFUNCTIONS.ASL.DM.NO.ITEMBATCHER.001

**Step Functions Distributed Map Lacks ItemBatcher Configuration**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SC-5; iso_27001_2022: A.8.16; nist_800_53_r5: SC-5, CM-7; soc2: CC8.1;

Distributed Map state has no `ItemBatcher` config when the input is large. Without batching, each item runs as a separate child execution — Standard pricing per state transition is paid per item, inflating cost. Downstream services that accept batches (DDB BatchWriteItem, Kinesis PutRecords) are also called per-item instead of per-batch.

**Remediation:** Add ItemBatcher with MaxItemsPerBatch matching downstream batch limit (DDB: 25, Kinesis: 500, Lambda: workload-dependent). Cost reduces by N× (batch-size factor).

---

### CTL.STEPFUNCTIONS.ASL.DM.NO.RESULTWRITER.001

**Step Functions Distributed Map Lacks ResultWriter For Large Outputs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4;

Distributed Map state has no `ResultWriter` configured. Map output is collected in-memory and capped at the 256 KB execution-payload limit. Aggregate output truncates silently when the limit is hit; downstream sees partial results without explicit signal. ResultWriter writes per-iteration outputs to S3, sidestepping the limit.

**Remediation:** Add ResultWriter pointing at an S3 bucket. Configure bucket policy to deny non-VPC writes and use SSE-KMS.

---

### CTL.STEPFUNCTIONS.ASL.DM.NO.TOLERANCE.001

**Step Functions Distributed Map Has No Failure Tolerance Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4, A1.2;

Distributed Map state has no `ToleratedFailureCount` or `ToleratedFailurePercentage`. A single child- iteration failure aborts the entire fan-out; partial results may be lost. Conversely a too-high tolerance hides failure rates that should page on-call. Both directions need explicit thresholds.

**Remediation:** Set ToleratedFailurePercentage: 1 (typical) or ToleratedFailureCount aligned with workload's acceptable error rate. Combine with ResultWriter to capture failed-iteration metadata.

---

### CTL.STEPFUNCTIONS.ASL.DM.S3.NOPREFIX.001

**Step Functions Distributed Map S3 Source Has No Prefix Filter**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.20, A.8.16; nist_800_53_r5: AC-3, SI-11; soc2: CC6.1, CC8.1;

Distributed Map's S3 `ItemReader` source has no `Prefix` filter set. Map iterates every object in the entire bucket. Cost-runaway surface (per-object state-transition charge) + possible cross-tenant data processing if the bucket holds multi-tenant data.

**Remediation:** Add Prefix to ItemReader pointing at the intended object subset. For multi-tenant buckets, Prefix should encode the tenant boundary (e.g., `tenants/<id>/`).

---

### CTL.STEPFUNCTIONS.ASL.FAIL.NOCAPTURE.001

**Step Functions Fail State Doesn't Capture Error Context To Persistent Store**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-3; iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-3, AU-12, IR-4; soc2: CC7.2, CC7.4;

ASL terminal `Fail` state (or terminal Catch handler routing to Fail) doesn't capture the error context to a persistent store — S3, CloudWatch, SNS, DDB. The execution history retains the error for ~90 days, then it's gone. Post-mortem of older failures has no source data; on-call response to repeat failures has no aggregate signal.

**Remediation:** Add a Task state before Fail that writes {execution_id, error_type, error_message, input, last_state_output} to S3 / DDB. Retain for incident-review window (typically 1y).

---

### CTL.STEPFUNCTIONS.ASL.MAP.LARGE.NOTDISTRIBUTED.001

**Step Functions Inline Map With Large Input Should Be Distributed Map**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11, SC-5; soc2: CC7.4, A1.1;

Inline (legacy) Map state runs with input arrays large enough to hit the inline limit (Standard: ~25,000 history events; Express: hard limit ~30 items in some builds). Beyond the inline limit, executions fail mid-run with no partial-result recovery. Distributed Map (ProcessorConfig.Mode: DISTRIBUTED) was introduced specifically to handle large inputs.

**Remediation:** Migrate to Distributed Map: add `ItemProcessor.ProcessorConfig.Mode: DISTRIBUTED`. Workflow definition shape changes; test thoroughly.

---

### CTL.STEPFUNCTIONS.ASL.MAP.MAXCONCURRENCY.ZERO.001

**Step Functions Map State Sets MaxConcurrency To Zero (Unlimited)**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11, SC-5; soc2: CC7.4, A1.1;

ASL `Map` state sets `MaxConcurrency: 0` — ASL semantics treat 0 as "no limit," same as the field being absent. Common confusion: operator intends "process zero items" or "default" but actually configures unbounded fan-out.

**Remediation:** Set explicit positive value (typical: 50). If "no concurrency" was intended, omit Map entirely.

---

### CTL.STEPFUNCTIONS.ASL.MAP.NOCATCH.001

**Step Functions Map State Lacks Catch Clause**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4, A1.2;

ASL `Map` state (inline or distributed) has no `Catch` clause. Single iteration failure aborts the whole Map; downstream cleanup is not defined. For distributed Map, failures can also bypass `ToleratedFailureCount` if the Map itself errors before iteration begins.

**Remediation:** Add Catch clause routing to compensation / failure state. For distributed Map, also configure `ToleratedFailureCount` / `ToleratedFailurePercentage`.

---

### CTL.STEPFUNCTIONS.ASL.MAP.NOMAXCONCURRENCY.001

**Step Functions Map State Has No MaxConcurrency Limit**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11, SC-5; soc2: CC7.4, A1.1;

ASL `Map` state has no `MaxConcurrency` field set. Map fans out per-iteration with no bounded parallelism — for a 10K-item input, 10K Lambda invocations land simultaneously, exhausting Lambda concurrent-execution reserves and throttling everything else in the account.

**Remediation:** Set MaxConcurrency to a value that won't saturate downstream (e.g., 50 for Lambda workloads where reserved concurrency is 1000). Tune based on Container Insights metrics on first run.

---

### CTL.STEPFUNCTIONS.ASL.PARALLEL.NOCATCH.001

**Step Functions Parallel State Lacks Catch Clause**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4, A1.2;

ASL `Parallel` state has no `Catch` clause. Failure in any child branch terminates the whole Parallel; surviving branches have no defined cleanup path. Compensating transactions, partial results, or branch- specific error reporting are impossible without a Catch.

**Remediation:** Add Catch clause routing to a compensation state. Track which branch failed via ResultPath: $.errorContext.

---

### CTL.STEPFUNCTIONS.ASL.QUERY.LANG.MISMATCH.001

**Step Functions ASL Uses JSONata Syntax With QueryLanguage JSONPath**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11, CM-3; soc2: CC7.4, CC8.1;

ASL definition contains expressions that look like JSONata syntax (e.g., `{% $variable %}`, `$contains()`) but the state machine's `QueryLanguage` field is `JSONPath` (or unset, defaulting to JSONPath). The expressions silently evaluate as literal strings rather than being interpreted — workflow runs but produces wrong output. The reverse mismatch (JSONPath syntax with QueryLanguage: JSONata) similarly degrades silently.

**Remediation:** Choose one query language at the state- machine level and ensure all expressions match. Migrating between the two requires re-writing every expression.

---

### CTL.STEPFUNCTIONS.ASL.RESULTPATH.NULL.001

**Step Functions Task Discards Output With ResultPath Null**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4;

ASL Task state has `ResultPath: null` — discards the Task's output entirely; next state sees the Task's input unchanged. Sometimes intentional (when the Task is a side-effect like SNS publish), but commonly a copy-paste mistake that breaks the downstream's expected data flow. Worse, it hides errors: a failed Task whose output contained the error code now appears identical to a successful one.

**Remediation:** Specify ResultPath that places output where downstream expects it. Use null only for side-effect Tasks where output is intentionally ignored, and document that intent.

---

### CTL.STEPFUNCTIONS.ASL.RETRY.NOATTEMPTS.001

**Step Functions Retry Clause With MaxAttempts Zero**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4, A1.2;

ASL `Retry` clause has `MaxAttempts: 0` — effectively disables retry. Transient failures (DDB throttling, Lambda cold-start timeout, SDK 5xx) propagate as task failure on first attempt. Standard mitigation for these is automatic retry; explicitly disabling it indicates retry was set up but never tuned, or a misunderstanding.

**Remediation:** Set MaxAttempts to a sensible value (3-5 for typical transient errors, with BackoffRate >= 2.0). Or remove the Retry block entirely if no retry is intended.

---

### CTL.STEPFUNCTIONS.ASL.RETRY.NOBACKOFF.001

**Step Functions Retry With BackoffRate 1.0 Hammers Downstream**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4, A1.1;

ASL `Retry` clause has `BackoffRate: 1.0` — flat retry interval, no exponential backoff. When the downstream is throttled or recovering, retries hit it at full rate, deepening the outage. Standard practice is BackoffRate >= 2.0 (each retry doubles the wait).

**Remediation:** Set BackoffRate >= 2.0; pair with IntervalSeconds >= 1 and MaxAttempts <= 5. Add MaxDelaySeconds (engine 2.x) to cap long backoffs.

---

### CTL.STEPFUNCTIONS.ASL.RETRY.STATES.ALL.001

**Step Functions Retry Matches States.ALL Including Non-Retryable Errors**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4;

ASL `Retry` matches `States.ALL` including permanent / non-retryable errors (States.Permissions, States.Runtime, validation failures). Retrying these is pointless — they will fail every attempt at the configured rate, just delaying the visible failure and wasting compute / downstream calls.

**Remediation:** Restrict to retryable transient errors (Lambda.ServiceException, Lambda.AWSLambdaException, States.Timeout, DynamoDB.ProvisionedThroughputExceeded).

---

### CTL.STEPFUNCTIONS.ASL.WAIT.HARDCODED.001

**Step Functions Wait State Uses Hardcoded Seconds Instead Of SecondsPath**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: CM-7; iso_27001_2022: A.8.32; nist_800_53_r5: CM-7; soc2: CC8.1;

ASL `Wait` state uses hardcoded `Seconds` instead of `SecondsPath` (or `TimestampPath`). Wait duration is fixed at definition time; per-execution tuning, dynamic backoff, or timeout adjustment requires UpdateStateMachine + new version. Operators commonly want to tune Wait without redeploy.

**Remediation:** Replace with SecondsPath that reads from workflow input or a Pass state's output. For polling patterns, use exponential increase based on retry count.

---

### CTL.STEPFUNCTIONS.BEDROCK.NOQUOTA.001

**Step Functions Bedrock Model Invocation Without Quota / Throttle Guard**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-7; iso_27001_2022: A.8.6; nist_800_53_r5: CM-7; soc2: CC8.1, A1.1;

Step Functions Task invokes Bedrock model (InvokeModel / Converse) without bounded invocation rate or quota guard. Bedrock bills per-token; runaway loops or large Map fan-out can incur substantial cost in minutes. Workflow should bound per-execution model calls (Map MaxConcurrency, Wait between calls, upstream input validation).

**Remediation:** Bound per-execution Bedrock calls via Map MaxConcurrency (e.g., 5) and upstream input validation (max items, max prompt length). Add Catch on Bedrock throttle errors with backoff.

---

### CTL.STEPFUNCTIONS.BREAKGLASS.PERMANENT.001

**Step Functions Operator Break-Glass states:* Role Permanently Active**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-2; iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-2, AC-6; pci_dss_v4.0: 7.2.4; soc2: CC6.1, CC6.3;

Organization has a break-glass IAM role with `states:*` permissions that is permanently assumable rather than gated behind a just-in-time elevation flow. Permanent break-glass = always-on workflow-admin capability for any caller in the trust policy.

**Remediation:** Move break-glass behind JIT elevation (AWS IAM Identity Center / Permission Sets with approval workflow).

---

### CTL.STEPFUNCTIONS.DDB.CONDITION.UNCAUGHT.001

**Step Functions DynamoDB UpdateItem Condition Failures Not Caught**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4;

Step Functions Task using DynamoDB UpdateItem with a `ConditionExpression` has no Catch on `DynamoDB.ConditionalCheckFailedException`. Conditional-write failures (item state drifted, version conflict) abort the workflow rather than retry / handle. Optimistic-locking patterns require explicit conflict handling.

**Remediation:** Add Catch on DynamoDB.ConditionalCheckFailedException routing to a re-read + retry path or to a documented conflict-resolution state.

---

### CTL.STEPFUNCTIONS.DELETION.PROTECTION.OFF.001

**Step Functions Production State Machine Has No Deletion Protection**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-3, CP-9; soc2: CC8.1, A1.2;

Step Functions production-tier state machine has no termination protection. A single DeleteStateMachine call (accidental, malicious, buggy automation) destroys the workflow irreversibly. Production state machines require an explicit deletion- protection flag or SCP guard.

**Remediation:** Apply tag-based SCP that denies DeleteStateMachine on production-tagged machines. Pair with versioning so rollback is possible if something does delete.

---

### CTL.STEPFUNCTIONS.DEV.PROD.DATA.001

**Step Functions Dev Region Workflow Processing Production Data**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.310(d); iso_27001_2022: A.5.10, A.8.20; nist_800_53_r5: AC-3, AC-21; soc2: CC1.5, CC6.1, CC8.1;

Step Functions state machine in a dev / staging region or dev / staging account is processing production data (e.g., reading from a prod-tagged S3 bucket, querying a prod DDB table). Compliance audits often require strict environment-data separation; debug-tier observability and IAM in dev makes prod data more reachable than intended.

**Remediation:** Cut prod-data access; replace with synthetic data fixtures. If a dev environment must validate against prod data, use a sanitized / pseudonymized snapshot.

---

### CTL.STEPFUNCTIONS.DM.NOTRACING.001

**Step Functions Distributed Map Has No Per-Iteration Tracing Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12; soc2: CC7.2;

Distributed Map child executions don't have X-Ray tracing or per-iteration logging enabled — debugging per-item failures requires reconstructing input from the parent's input source. For workflows fan-out to thousands of items, this is operationally intractable.

**Remediation:** Enable child-execution X-Ray; pair with ResultWriter so per-iteration metadata captures input + outcome. Tag traces with item index for queryability.

---

### CTL.STEPFUNCTIONS.DR.NOSECONDREGION.001

**Step Functions Production Standard Workflow Not Deployed To DR Region**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-7; iso_27001_2022: A.8.13, A.8.14; nist_800_53_r5: CP-7, CP-9; soc2: CC7.4, A1.2;

Step Functions production-tier Standard workflow has no equivalent deployed to a DR region. Region-failure event takes the workflow offline; restore is from-scratch rather than failover. IaC for the workflow doesn't include a region-equivalent configuration.

**Remediation:** Replicate IaC to DR region. Pair with multi-region KMS, multi-region tables, multi-region Lambda. Test failover quarterly.

---

### CTL.STEPFUNCTIONS.EB.SHARED.MACHINE.001

**Step Functions State Machine ARN Targeted By Many EventBridge Rules**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-7; iso_27001_2022: A.8.14; nist_800_53_r5: CP-7; soc2: A1.1, A1.2;

One Step Functions state machine is the target of more than 10 EventBridge rules. Single point of failure for many event flows; one workflow defect impacts every feeding rule. Maintenance changes (deploy, pause, IAM update) cascade across all consumers without their owners knowing.

**Remediation:** Split workflow by rule consumer-class. Or document dependency explicitly so each rule's owner knows their downstream is shared.

---

### CTL.STEPFUNCTIONS.EB.UNVERSIONED.ARN.001

**Step Functions EventBridge Rule Targets Unversioned State Machine ARN**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.8.32; nist_800_53_r5: CM-3; soc2: CC8.1, A1.2;

EventBridge rule targets a Step Functions state machine using its unversioned ARN. Each new alias / version is automatically exposed via the rule. If a deploy publishes a buggy version, the rule starts firing the bug immediately — alias-based canary has no effect.

**Remediation:** Update rule's Target to use the alias ARN. If multiple environments need different aliases, add per-env rules.

---

### CTL.STEPFUNCTIONS.EMR.SERVERLESS.NOTIMEOUT.001

**Step Functions EMR Serverless .sync Job Without Configured Timeout**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-7; iso_27001_2022: A.8.6; nist_800_53_r5: CM-7; soc2: CC8.1, A1.1;

Step Functions Task using EMR Serverless `.sync` integration runs a job without an explicit job-runtime timeout. EMR Serverless bills per second of compute; runaway jobs incur cost until the workflow's overall timeout (or no timeout — billing indefinitely).

**Remediation:** Pass `executionTimeoutMinutes` in the Parameters. Document expected runtime based on input shape.

---

### CTL.STEPFUNCTIONS.ENCRYPT.DEFINITION.AWSOWNED.001

**Step Functions State Machine Definition Encrypted With AWS-Owned Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.7;

Step Functions state machine definition is encrypted with an AWS-owned key (default) rather than a customer-managed KMS key. AWS-owned keys are not auditable, can't be selectively revoked, and can't be rotated on a customer schedule. For regulated workloads (HIPAA, PCI, SOC2), customer- managed keys are required.

**Remediation:** Re-create state machine with EncryptionConfiguration referencing a customer-managed CMK. Migration is blue-green; existing executions complete on the old key.

---

### CTL.STEPFUNCTIONS.ENCRYPT.EXEC.OFF.001

**Step Functions Execution Input/Output Not Encrypted With Customer Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv), 164.312(e)(2)(ii); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.7;

Step Functions execution input and output payloads are not encrypted with a customer- managed KMS key. Execution data persists in the execution history and (when IncludeExecutionData is on) in CloudWatch Logs. Without per-execution KMS encryption, these payloads are protected only by AWS service-level encryption — adequate for general data, insufficient for regulated PII / PHI / PCI-scope workloads.

**Remediation:** Configure EncryptionConfiguration with KmsDataKeyReusePeriodSeconds and KmsKeyId pointing at a customer-managed CMK. Documentation: docs.aws.amazon.com/step- functions/latest/dg/encryption-at-rest.

---

### CTL.STEPFUNCTIONS.ENCRYPT.KEY.DRIFT.001

**Step Functions Definition And Execution KMS Keys Differ**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-12; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, CM-3; soc2: CC6.7, CC8.1;

Step Functions state machine's definition encryption key differs from the per- execution data encryption key. Operators rotating one key out without rotating the other lose the ability to read either old definitions or old execution histories. Compliance / forensic recovery requires both keys; key custody must be coherent.

**Remediation:** Align both EncryptionConfiguration KmsKeyId references to the same customer-managed CMK. Document the key custody decision. For multi-region DR, use a multi-region KMS key.

---

### CTL.STEPFUNCTIONS.ENCRYPT.KMS.NOMULTIREGION.001

**Step Functions KMS Key Single-Region Without Multi-Region Configuration**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: CP-7; iso_27001_2022: A.8.24, A.8.14; nist_800_53_r5: CP-7, SC-12; soc2: CC7.4, A1.2;

Step Functions state machine's KMS key is a single-region key. Cross-region disaster recovery requires a multi-region key (or manually replicated key material) — without it, restored state machines and execution histories in the alternate region cannot be decrypted. Region-failure DR plans that assume cross-region recovery fail at the KMS layer.

**Remediation:** Create a multi-region key and replicate to the DR region. Migrate the state machine to use the multi-region key (blue-green). Document the recovery procedure.

---

### CTL.STEPFUNCTIONS.ENCRYPT.KMS.NOROTATION.001

**Step Functions KMS Key Has Automatic Rotation Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-12; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12; owasp_nhi: NHI7; pci_dss_v4.0: 3.6.4; soc2: CC6.7, CC8.1;

Step Functions state machine's KMS key has automatic rotation disabled. AWS rotates the key material annually when enabled; without it, the same material protects data indefinitely. NIST / PCI-DSS guidance recommends automatic rotation for keys with long-lived data.

**Remediation:** Enable automatic rotation:
  aws kms enable-key-rotation
    --key-id <key-id>
Effective annually; safe for symmetric keys (no client coordination needed).

---

### CTL.STEPFUNCTIONS.ENCRYPT.LOG.SECRET.LEAK.001

**Step Functions IncludeExecutionData Captures Secrets To CloudWatch Logs**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.5.34, A.8.24; nist_800_53_r5: SC-28, SI-12; pci_dss_v4.0: 3.4.1, 3.5.1; soc2: CC6.1, CC6.7;

Step Functions has `IncludeExecutionData: true` on a workflow whose payloads contain secrets / PII / PHI without input/output redaction. Logs end up holding the sensitive data; anyone with CloudWatch Logs read access reads it. The right pattern is IncludeExecutionData: true PLUS explicit redaction (Pass state mapping that strips secret fields) before the log-captured states.

**Remediation:** Add a redaction Pass state that maps sensitive fields away from the payload before any state-with-Catch (and thus before logging captures the payload). Reference SecretsManager via `arn:aws:states:::aws-sdk:secretsmanager: getSecretValue` rather than embedding.

---

### CTL.STEPFUNCTIONS.EVENTBRIDGE.STATUS.001

**Step Functions Status Change Events Not Subscribed In EventBridge**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12, IR-6; soc2: CC7.2, CC8.1;

No EventBridge rule subscribed to Step Functions `Execution Status Change` or `State Machine Status Change` events. Without these rules, terminal-state events (SUCCEEDED, FAILED, ABORTED, TIMED_OUT) and state-machine config changes (CREATE, UPDATE, DELETE) flow only to the audit log — no real-time hooks for downstream processing or notification.

**Remediation:** Create rules: source aws.states, detail-type "Step Functions Execution Status Change" and "Step Functions State Machine Status Change". Route to SNS / Slack / SIEM.

---

### CTL.STEPFUNCTIONS.EXECUTION.HISTORY.RETENTION.001

**Step Functions Old Execution History Not Configured For Retention Or Archival**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-11; hipaa: 164.530(j); iso_27001_2022: A.5.33; nist_800_53_r5: AU-11; pci_dss_v4.0: 10.5.1; soc2: CC7.2;

Step Functions Standard execution history retains for ~90 days then is purged. Without explicit archival (CloudWatch Logs → S3 export, EventBridge → archive), forensic / compliance access to past executions ends at 90 days. Not directly a cost issue, but governance discipline that should accompany cost-tuning.

**Remediation:** Subscribe `Execution Status Change` events (SF-5 control covers this); archive to S3 with lifecycle. Or wire CloudWatch Logs to Kinesis Firehose → long-retention S3.

---

### CTL.STEPFUNCTIONS.HISTORY.NOAUTOARCHIVE.001

**Step Functions Old Executions Not Auto-Archived To Cold Storage**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-11; iso_27001_2022: A.5.33; nist_800_53_r5: AU-11; pci_dss_v4.0: 10.5.1; soc2: CC7.2;

Step Functions Standard execution history ages out at ~90 days; without auto-archive, old execution data is gone for good. Even with EventBridge Status-Change events exported (SF-5), the per-step detail history doesn't survive. For long-tail audit, configure scheduled GetExecutionHistory + S3 export.

**Remediation:** Schedule a daily / weekly Lambda that pages GetExecutionHistory for all completed-and-aged executions and writes to S3 with lifecycle.

---

### CTL.STEPFUNCTIONS.IAC.COMPLIANCE.DRIFT.001

**Step Functions IaC Configuration Drifts Between Regulated And Non-Regulated Envs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.5.10, A.8.32; nist_800_53_r5: CM-3, CA-7; soc2: CC1.5, CC8.1;

Step Functions IaC modules used for regulated workflows differ from those used for non-regulated workflows in ways that break the "regulated workflows inherit at-least-as-strict" property: e.g., regulated has Level: ALL logging but a non-regulated env's module sets Level: ERROR, and code-shared between envs fingerprints both at the looser setting.

**Remediation:** Audit IaC module fingerprints across envs. Reconcile via shared "regulated" module that non-regulated envs can opt into but cannot weaken.

---

### CTL.STEPFUNCTIONS.IAC.CONSOLE.DRIFT.001

**Step Functions State Machine Modified Outside IaC (Console Drift)**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3; soc2: CC8.1, CC7.1;

Step Functions state machine's most recent configuration change (UpdateStateMachine) was performed by an IAM principal that is not the IaC automation role. Direct console / CLI changes bypass IaC review and create state divergence. Either next IaC apply reverts the change, or operators back-port it manually without review.

**Remediation:** Identify via CloudTrail (eventName= UpdateStateMachine, source IP / userIdentity). Reproduce in IaC; revert if unauthorized. Add CloudWatch alarm: UpdateStateMachine events from non-IaC principals.

---

### CTL.STEPFUNCTIONS.IAC.OWNERSHIP.001

**Step Functions IaC Module Lacks Ownership / On-Call Tags**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-8; iso_27001_2022: A.5.9, A.5.30; nist_800_53_r5: CM-8, IR-6; soc2: CC8.1, A1.1;

Step Functions state machine's IaC module lacks `owner` and `oncall-rotation` tags pointing at a maintainer team. During incidents, on-call has no quick path to the owner; for production-tier workflows this delays response.

**Remediation:** Add `owner` (team email or PagerDuty rotation), `oncall-rotation` (rotation name), `runbook` (URL). Enforce via tag-policy SCP.

---

### CTL.STEPFUNCTIONS.IAM.CROSSACCOUNT.NOEXTERNAL.001

**Step Functions Cross-Account StartExecution Without ExternalId**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.16, A.8.20; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2.4; soc2: CC6.1, CC6.6;

Step Functions cross-account `states:StartExecution` grant lacks an `sts:ExternalId` condition. Any role in the foreign account can assume into the trusted role and start executions — classic confused-deputy. ExternalId binds the trust to a specific tenant / integration.

**Remediation:** Add sts:ExternalId condition matching the integration's known external ID. Distribute the ExternalId out-of-band.

---

### CTL.STEPFUNCTIONS.IAM.CROSSACCOUNT.NOSRC.001

**Step Functions Cross-Account Grant Without aws:SourceAccount Condition**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.16, A.8.20; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2.4; soc2: CC6.1, CC6.6;

Step Functions IAM resource-based or identity- based policy grants states:* actions to a principal in a different AWS account but lacks an `aws:SourceAccount` (or equivalent `aws:SourceArn`) condition. The grant is open to any caller from the foreign account regardless of which workflow / role is intended.

**Remediation:** Add condition: aws:SourceAccount equals the expected account, or aws:SourceArn pinned to the specific calling resource.

---

### CTL.STEPFUNCTIONS.IAM.CROSSACCOUNT.WILDCARD.001

**Step Functions Cross-Account Principal Granted Action Wildcard**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2.1, 7.2.4; soc2: CC6.1, CC6.3;

Step Functions resource-based policy grants `states:*` (or another action wildcard) to a principal in a different AWS account. Cross- account + action wildcard = compromise of any identity in the foreign account yields full Step Functions control over the granted state machine.

**Remediation:** Narrow grant to specific actions (StartExecution, DescribeExecution). Combine with sts:ExternalId for confused-deputy protection.

---

### CTL.STEPFUNCTIONS.IAM.NORESOURCETAG.001

**Step Functions IAM Policies Don't Use aws:ResourceTag For Scoping**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-6; soc2: CC6.1, CC6.3;

Step Functions IAM policies don't use `aws:ResourceTag/*` conditions to scope by team / environment / compliance class. Single IAM role hits all state machines in the account; per-team / per-env isolation requires per-machine policy duplication. ABAC is the AWS-recommended pattern for scaling authorization.

**Remediation:** Add condition: aws:ResourceTag/team equals aws:PrincipalTag/team. Tag state machines with team / env. Audit Access Analyzer findings for over-permissive grants.

---

### CTL.STEPFUNCTIONS.IAM.OPS.BROAD.001

**Step Functions Disruption / Tag Permissions Granted Broadly**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6; soc2: CC6.1, CC8.1;

IAM policy grants `states:StopExecution` and / or `states:TagResource` / `states:UntagResource` broadly (e.g., on Resource:* or to a non-operations role). StopExecution is a denial-of-service surface (any caller can interrupt running workflows). TagResource manipulation breaks cost allocation, ABAC scoping, and compliance reporting.

**Remediation:** Restrict StopExecution to operator roles. Restrict TagResource / UntagResource to deployment / governance roles. Both should target specific machine ARNs not Resource:*.

---

### CTL.STEPFUNCTIONS.IAM.STALE.RULE.001

**Step Functions IAM Policy Has Stale Temporary Allow Rule**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.27; nist_800_53_r5: AC-6, CA-7; soc2: CC6.1, CC8.1;

Step Functions IAM policy contains a statement marked or commented as temporary (operator's IP, contractor's vendor CIDR, debugging exception) older than 90 days. Temporary rules accumulate as nobody owns removal; each is an unreviewed allow path on the workflow.

**Remediation:** Quarterly access-review: identify temporary statements (Sids tagged temp- / commented), promote to permanent or remove. Encode expiry date in Sid for mechanical review.

---

### CTL.STEPFUNCTIONS.IAM.STARTEXEC.ALLMACHINE.001

**Step Functions StartExecution On All-Machine Resource Pattern**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1, 7.2.2; soc2: CC6.1, CC6.3;

IAM policy grants `states:StartExecution` on `Resource: "arn:aws:states:*:*:stateMachine/*"` (or the per-region equivalent). Role can start any state machine in any region, not just the intended one. Most workloads need StartExecution on a single ARN.

**Remediation:** Pin Resource to specific state-machine ARN. Use ABAC (aws:ResourceTag) for multi-machine grants where appropriate.

---

### CTL.STEPFUNCTIONS.IAM.STARTEXEC.WILDCARD.001

**Step Functions StartExecution Granted To Wildcard Principal**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Step Functions state machine has an IAM policy granting `states:StartExecution` to `Principal: "*"` without conditions. Any AWS identity (or anonymous, depending on path) can start executions of this state machine, consuming downstream Lambda / DDB / SNS resources at the workflow's full IAM authority.

**Remediation:** Replace Principal: "*" with specific role ARNs that need to start executions. Add `aws:SourceAccount` / `aws:SourceArn` conditions for cross-account integrations.

---

### CTL.STEPFUNCTIONS.IAM.STATES.WILDCARD.001

**Step Functions IAM Policy Grants states:* On Resource:***

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1, 7.2.2; soc2: CC6.1, CC6.3;

IAM policy grants `states:*` on `Resource: "*"` without scoping by tag, account, or specific state machine ARN. Roles holding this policy can create, update, delete, start, and stop every state machine in the account. Most workloads need just StartExecution / Describe on a single ARN.

**Remediation:** Narrow to the specific actions the role needs (StartExecution, DescribeExecution) on the specific state machine ARN. Reserve states:* for admin / break-glass with sign-off.

---

### CTL.STEPFUNCTIONS.IAM.UPDATE.NONADMIN.001

**Step Functions Control-Plane Actions Granted To Non-Admin Roles**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6, CM-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1, CC6.3, CC8.1;

Non-admin role granted Step Functions control- plane actions: `states:CreateStateMachine`, `states:UpdateStateMachine`, or `states:DeleteStateMachine`. Compromise of the role enables attacker to define new workflows, rewrite existing definitions (including pivoting to an attacker-controlled execution role), or destroy production workflows.

**Remediation:** Restrict CreateStateMachine / UpdateStateMachine / DeleteStateMachine to a documented admin role with break-glass sign-off. Remove from automation / deployment roles unless they have explicit workflow-management mandate.

---

### CTL.STEPFUNCTIONS.IDEMPOTENCY.NAME.001

**Step Functions StartExecution Names Not Unique Per Logical Operation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4;

Step Functions caller doesn't pass a unique `name` to StartExecution per logical operation. Step Functions deduplicates by name within a 90-second window — identical names within that window silently return the same execution ARN. Without deliberate name-as-idempotency-key, two retry attempts at the EXACT same moment collide; later retries (>90s) succeed causing duplicates.

**Remediation:** Pass an explicit name derived from the logical operation ID (order-id, request-id). Document the dedup window explicitly. For long-window dedup, track submitted IDs in DynamoDB before StartExecution.

---

### CTL.STEPFUNCTIONS.IDLE.MACHINE.001

**Step Functions State Machine Idle With No Executions In 30+ Days**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-8; iso_27001_2022: A.5.9, A.8.10; nist_800_53_r5: CM-8; soc2: CC8.1;

Step Functions state machine has had no executions in 30+ days. Dead inventory: contributes to IAM permission surface, retains historical event log entries that consume storage, and complicates inventory audits.

**Remediation:** Decide: decommission and delete state machine + role, or document active intent (e.g., DR / seasonal). If keeping, tag accordingly so periodic review skips it.

---

### CTL.STEPFUNCTIONS.LAMBDA.CALLBACK.NOHEARTBEAT.001

**Step Functions Lambda Callback Function Doesn't Honor Heartbeat**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4;

Step Functions Task uses Lambda with `.waitForTaskToken` callback pattern but the Lambda function code doesn't call `SendTaskHeartbeat` periodically before completion. If Task has HeartbeatSeconds set, Lambda exceeding it triggers `States.Heartbeat` even when Lambda is still doing valid work.

**Remediation:** Add periodic `SendTaskHeartbeat` calls in Lambda code (e.g., once per 30s in a long-running iteration). Or remove HeartbeatSeconds from the Task if no progress signal is needed.

---

### CTL.STEPFUNCTIONS.LAMBDA.CROSSREGION.001

**Step Functions Lambda Function In Different Region Than State Machine**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.5.10, A.8.20; nist_800_53_r5: SC-7, CM-7; soc2: CC8.1, A1.1;

Step Functions Task references a Lambda function in a different AWS region than the state machine. Cross-region invocation has additional latency, doubled cost (data transfer), and complicates compliance scope (data may cross residency boundaries). Production workflows should keep Lambda in the same region.

**Remediation:** Move Lambda to the workflow's region. For multi-region workflows, deploy per-region state machines + per-region Lambdas; avoid cross-region Lambda calls.

---

### CTL.STEPFUNCTIONS.LAMBDA.DLQ.MISSING.001

**Step Functions Lambda Function Async Invocation DLQ Not Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11, AU-12; soc2: CC7.4, A1.2;

Lambda function called via async invocation pattern (e.g., from Step Functions Map with high concurrency, or from EventBridge → Step Functions → Lambda chain) has no Dead Letter Queue configured. Lambda's internal retries can run out; without DLQ, the failure record is lost. For workflows that need at-least-once semantics on Lambda invocation, DLQ is required.

**Remediation:** Configure DeadLetterConfig on the Lambda function pointing at SQS / SNS. Alarm on DLQ object count > 0 for prompt investigation.

---

### CTL.STEPFUNCTIONS.LAMBDA.LOG.UNCORRELATED.001

**Step Functions Lambda Logs Not Correlatable With Workflow Execution Logs**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-3; iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-3, AU-12; soc2: CC7.2;

Lambda function called from Step Functions doesn't log the workflow's execution ID (passed via `$$.Execution.Id` context object). When debugging a failed execution, operators must correlate Lambda logs by timestamp — fragile and slow. Standard practice: include execution ID in every Lambda log line.

**Remediation:** Pass `$$.Execution.Id` as a Parameters field; Lambda code logs it on every output line. Index Lambda logs in CloudWatch Logs Insights with the execution ID as a queryable field.

---

### CTL.STEPFUNCTIONS.LAMBDA.RES.POLICY.MISMATCH.001

**Step Functions Lambda Reference Doesn't Match Function's Resource Policy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.20; nist_800_53_r5: AC-3, SI-11; soc2: CC6.1, A1.2;

Step Functions Task references a Lambda function whose resource-based policy does not include `states.amazonaws.com` (with the right `aws:SourceArn` matching this state machine). Invocation fails at runtime with `AccessDenied`. Common after re- parenting a Lambda or when the Lambda was created by a different team.

**Remediation:** Add a statement to the Lambda's resource policy:
  Principal: states.amazonaws.com,
  Action: lambda:InvokeFunction,
  Condition: {
    StringEquals: {
      aws:SourceArn: <state-machine-arn>
    }
  }

---

### CTL.STEPFUNCTIONS.LAMBDA.RESOURCE.LATEST.001

**Step Functions Lambda Task References $LATEST Function Version**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.8.32; nist_800_53_r5: CM-3; soc2: CC8.1, A1.2;

Step Functions Task `Resource` references a Lambda function ARN ending in `:$LATEST` or with no version qualifier (defaulting to $LATEST). Each new Lambda deploy mutates the version $LATEST points at; in-flight workflow executions hit the new code mid-run. Production workflows should pin to a versioned alias (`:prod`) or specific version (`:42`).

**Remediation:** Pin to a versioned alias the deploy pipeline updates atomically (e.g., `:prod`). Use weighted alias routing for canary.

---

### CTL.STEPFUNCTIONS.LAMBDA.ROLE.DRIFT.001

**Step Functions Lambda Execution Role Diverges From Workflow Role**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6; soc2: CC6.1, CC6.3;

Lambda function called from a Step Functions Task has an execution role with permission scope significantly different from the state machine's execution role. The workflow's IAM is what operators audit; the Lambda's IAM hides the actual reach of the workflow. Common pattern: workflow role is tightly scoped, Lambda role has `*:*` "for development."

**Remediation:** Audit Lambda execution role permissions against workflow role. Where Lambda needs broader scope, document why; where not, narrow the Lambda role to match. Use IAM Access Analyzer's unused- access findings.

---

### CTL.STEPFUNCTIONS.LAMBDA.TIMEOUT.GT.TASK.001

**Step Functions Lambda Function Timeout Exceeds Task TimeoutSeconds**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.8.32; nist_800_53_r5: CM-3, SI-11; soc2: CC8.1, A1.1;

Lambda function's runtime `Timeout` setting is greater than the Step Functions Task's `TimeoutSeconds`. Task times out before Lambda completes; the Lambda continues running (and billing) but its output is discarded — Step Functions has already taken the timeout-error path. Result: cost for work the workflow couldn't use.

**Remediation:** Set Task TimeoutSeconds >= Lambda Timeout + small margin (e.g., +10s). Or shorten Lambda Timeout if the workflow truly cannot wait.

---

### CTL.STEPFUNCTIONS.LAMBDA.UNPINNED.001

**Step Functions Lambda Task Has No Alias / Version Pin**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.8.32; nist_800_53_r5: CM-3; soc2: CC8.1;

Step Functions Task `Resource` references a Lambda function without any alias or version qualifier (e.g., `arn:aws:lambda:::function:my-fn` rather than `:my-fn:prod`). Same effect as $LATEST but harder to spot in inventory because the ARN looks "explicit." Pin to alias for versioned routing.

**Remediation:** Add `:prod` (or environment-appropriate alias) to every Lambda Resource ARN. CI enforces pin via terraform / CDK lint.

---

### CTL.STEPFUNCTIONS.LOG.001

**Step Functions State Machines Must Have Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

Step Functions state machines must emit execution logs to CloudWatch Logs. Without logging, workflow execution details and errors are invisible.

**Remediation:** Enable execution logging to CloudWatch Logs.

---

### CTL.STEPFUNCTIONS.LOG.COST.RUNAWAY.001

**Step Functions Log Cost Runaway From Express + ALL Logging Or Standard ALL**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-7; iso_27001_2022: A.8.6; nist_800_53_r5: CM-7; soc2: CC8.1;

Step Functions logging configuration produces high CloudWatch Logs volume: Express workflow with `Level: ALL` (high per-event ingest cost; ingest >> Express per-request cost), or Standard workflow with `Level: ALL` and high event-rate. CloudWatch Logs ingestion bills per GB — log cost can dwarf compute cost.

**Remediation:** Lower Level (FATAL or ERROR for high-vol Express; INFO for Standard). Add log-volume CloudWatch alarm. Use Kinesis Firehose subscription with S3 export + lifecycle for cost-effective retention.

---

### CTL.STEPFUNCTIONS.LOG.EXPRESS.UNARCHIVED.001

**Step Functions Express Workflow Logs Not Exported To Long-Retention Store**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-11; iso_27001_2022: A.5.33, A.8.15; nist_800_53_r5: AU-11; pci_dss_v4.0: 10.5.1; soc2: CC7.2;

Express workflow logs go only to CloudWatch with default retention. Unlike Standard (which retains execution history for ~90 days via the API), Express has no API history at all — logs are the only record. Without long-retention archival (S3 export, SIEM ingestion), evidence beyond the CWL retention window is gone.

**Remediation:** Add log subscription filter exporting to Kinesis Firehose → S3 (or SIEM ingest). Apply S3 lifecycle for cost control.

---

### CTL.STEPFUNCTIONS.LOG.GROUP.MISSING.001

**Step Functions Log Destination CloudWatch Group Does Not Exist**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-3; iso_27001_2022: A.8.15; nist_800_53_r5: AU-3, AU-12; pci_dss_v4.0: 10.4.1; soc2: CC7.2, A1.2;

Step Functions log configuration references a CloudWatch Log group that does not exist. Log delivery silently drops events — the state machine reports logging-enabled, the pipeline appears healthy from inventory, but no events arrive at any consumer. Common pattern: log group renamed or deleted by another team without checking which services delivered to it.

**Remediation:** Re-create the log group or repoint via UpdateStateMachine --logging-configuration. Verify with describe-state-machine.

---

### CTL.STEPFUNCTIONS.LOG.LEVEL.LOW.001

**Step Functions Log Level Set To OFF Or ERROR Only**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-2; iso_27001_2022: A.8.15; nist_800_53_r5: AU-2, AU-3, AU-12; pci_dss_v4.0: 10.2.1, 10.2.2; soc2: CC7.2;

Step Functions logging is enabled but `Level` is `OFF` (effectively no logs) or `ERROR` (only failures captured). Successful executions, state transitions, retry events, and Catch-handled errors all go unrecorded. Without this signal, post-mortem of a silent failure or behavior drift is impossible.

**Remediation:** Set Level to ALL on production-tier workflows; FATAL or ERROR is acceptable only for very-high-cardinality or known- benign workflows. Pair with IncludeExecutionData: true for full diagnostic context.

---

### CTL.STEPFUNCTIONS.LOG.NOEXEC.DATA.001

**Step Functions Standard Workflow IncludeExecutionData Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-3; hipaa: 164.312(b); iso_27001_2022: A.8.15; nist_800_53_r5: AU-3, AU-12; pci_dss_v4.0: 10.2.5; soc2: CC7.2;

Step Functions Standard workflow has `IncludeExecutionData: false`. Logs capture state-transition events but not the input / output payloads. During incident review, the operator sees "state X completed at timestamp T" but cannot reconstruct what data flowed through the workflow. For workflows handling regulated data, this is also a compliance gap (state changes without event content fail HIPAA AU-3).

**Remediation:** Set logging.IncludeExecutionData: true. Increase log retention budget; payloads are larger than transition events alone. For workflows handling secrets, redact sensitive fields via input/output transformations BEFORE entering log-captured states.

---

### CTL.STEPFUNCTIONS.LOG.RETENTION.SHORT.001

**Step Functions Log Group Retention Below Compliance Window**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-11; hipaa: 164.530(j); iso_27001_2022: A.5.33; nist_800_53_r5: AU-11; pci_dss_v4.0: 10.5.1; soc2: CC7.2;

Step Functions log destination CloudWatch group has retention < 365 days (the most permissive common regulatory minimum). HIPAA requires 6 years, PCI-DSS 1 year, SOX 7 years. Logs that age out before the retention window create an audit / forensic gap regardless of how thoroughly they were collected.

**Remediation:** Update CWL retention to match compliance scope; pair with S3 Glacier export for long retention (HIPAA: 2557, PCI: 365, SOX: 2557).

---

### CTL.STEPFUNCTIONS.NAME.COLLISION.001

**Step Functions Multiple State Machines Share The Same Name Across Environments**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-8; iso_27001_2022: A.5.9; nist_800_53_r5: CM-8; soc2: CC8.1;

Multiple Step Functions state machines share the same name across accounts / environments (e.g., `process-orders` in dev, staging, and prod). Operators referring to "the process-orders state machine" must always disambiguate by account. Cross-environment IaC promotion scripts can target the wrong one.

**Remediation:** Suffix names with environment (`process-orders-prod`, `process-orders-dev`). Or use account- isolation only and avoid cross-account name confusion via runbook discipline.

---

### CTL.STEPFUNCTIONS.NOTAGS.001

**Step Functions State Machine Missing Cost / Environment / Compliance Tags**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-8; iso_27001_2022: A.5.9, A.5.30; nist_800_53_r5: CM-8, PM-3; soc2: CC8.1;

Step Functions state machine has no `cost-center`, `team`, `owner`, `environment`, or `compliance-scope` tags. Cost allocation can't roll up by team / project; environment-class can't be determined from inventory; compliance scoping (HIPAA / PCI / SOC2 / GDPR) requires manual lookup per machine.

**Remediation:** Apply tags: cost-center, team, owner, environment, compliance-scope. Activate AWS Cost Allocation Tags via Billing Console. Enforce via tag policy + SCP.

---

### CTL.STEPFUNCTIONS.RATE.LIMIT.NONOTIFY.001

**Step Functions No Notification On StartExecution Rate Throttling**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12, SI-4; soc2: CC7.2, A1.1;

Step Functions IAM role used to invoke StartExecution has no rate-limit on the caller side, and no CloudWatch alarm / EventBridge rule configured to notify on approach to the StartExecution burst / account-level concurrent quota. Sudden bursts (event-storm scenarios) silently exhaust quota; downstream consumers see failed invocations without traceable source.

**Remediation:** Create CloudWatch alarm: ExecutionsStarted rate > 80% of region quota. Subscribe on-call to detect surges before quota is hit.

---

### CTL.STEPFUNCTIONS.REGION.UNAUTHORIZED.001

**Step Functions State Machine In Unauthorized Region**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.310(d); iso_27001_2022: A.5.10, A.5.34; nist_800_53_r5: AC-3, CA-7; pci_dss_v4.0: 12.10.1; soc2: CC1.5, CC6.1;

Step Functions state machine deployed in an AWS region not on the org's authorized list. Data residency requirements (GDPR EU-only, country-specific data laws) and internal policy violated. Common cause: dev experiment promoted to production without region review.

**Remediation:** Re-deploy in authorized region; migrate in-flight execution state via state-machine restart in target region. DeleteStateMachine in unauthorized region. Verify via organizations:DescribeOrganization + aws:RequestedRegion SCP guard.

---

### CTL.STEPFUNCTIONS.ROLE.COMPLIANCE.REUSE.001

**Step Functions IAM Role Re-Used Across Compliance Boundaries**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.308(a)(4); iso_27001_2022: A.5.10, A.5.15; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2.4; soc2: CC1.5, CC6.1;

Step Functions execution role is shared between workflows in different compliance scopes (e.g., HIPAA-scoped workflow shares role with non-HIPAA workflow). Audit scope for the role must include both worlds; any compliance reduction in one workflow affects the other; per-scope IAM conditions break.

**Remediation:** Split role per compliance scope. Document scope tags on each role. Pair with ABAC: aws:ResourceTag/compliance-scope must match aws:PrincipalTag/compliance-scope.

---

### CTL.STEPFUNCTIONS.ROLE.IDLE.MACHINE.001

**Step Functions Execution Role Attached To Idle State Machine**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-2; iso_27001_2022: A.5.16, A.8.10; nist_800_53_r5: AC-2, CM-8; soc2: CC8.1;

Execution role attached to a state machine that has had no executions in 90+ days. The state machine is dead inventory; its role remains assumable and contributes to the account's effective permission surface for no operational benefit. Often accompanied by the role's permissions still pointing at decommissioned downstream resources.

**Remediation:** Decide: decommission the state machine and delete its role, or document active intent. If the machine is dormant by design (DR / seasonal), tag accordingly so periodic review skips it.

---

### CTL.STEPFUNCTIONS.ROLE.NOCONDITIONS.001

**Step Functions Execution Role Lacks Defense-In-Depth Condition Keys**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-6; soc2: CC6.1;

Execution role's identity-based policies have no defense-in-depth condition keys — `aws:RequestedRegion`, `aws:CalledVia`, `aws:SourceVpc`, `aws:VpcSourceIp`. Granted actions execute regardless of where the call comes from. Conditions reduce blast radius during a credential-leak incident: stolen credentials are useless from outside the expected region or service path.

**Remediation:** Add condition: aws:RequestedRegion equals the workflow's region. For VPC-bound workflows, add aws:SourceVpc / aws:SourceVpce. For CalledVia: states. amazonaws.com to ensure the role is only callable via Step Functions.

---

### CTL.STEPFUNCTIONS.ROLE.PERM.DYNAMODB.WILDCARD.001

**Step Functions Execution Role Grants dynamodb:* On Wildcard Resource**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1, CC6.3;

Execution role grants `dynamodb:*` on `Resource: "*"`. State machine can read, write, or delete every DynamoDB table in the account. Workflow input or definition compromise becomes total DynamoDB authority for the workflow's region.

**Remediation:** Restrict to specific table ARNs and the minimum action set (PutItem / GetItem / Query / UpdateItem). Reserve DeleteTable / DeleteItem for explicit workflow steps that need them.

---

### CTL.STEPFUNCTIONS.ROLE.PERM.LAMBDA.WILDCARD.001

**Step Functions Execution Role Grants lambda:InvokeFunction On Wildcard Resource**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1, CC6.3;

Execution role grants `lambda:InvokeFunction` on `Resource: "*"` instead of specific function ARNs. State machine can invoke any Lambda in the account, not just its own task functions. Compromise of the workflow input or definition becomes a path to invoke arbitrary Lambdas.

**Remediation:** Pin Resource to specific function ARNs (or aliases / versions) referenced by the state machine. Use ABAC for many-function cases.

---

### CTL.STEPFUNCTIONS.ROLE.PERM.MESSAGING.WILDCARD.001

**Step Functions Execution Role Grants Messaging Actions On Wildcard Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Execution role grants `sns:Publish`, `sqs:SendMessage`, or `events:PutEvents` on `Resource: "*"`. Workflow can publish to any topic, send to any queue, or inject events on any bus in the account — exfiltration channels (SNS to email/SMS/HTTPS endpoints) and event-bus injection (triggering arbitrary EventBridge rules) are open.

**Remediation:** Pin to specific topic / queue / event-bus ARNs the workflow actually uses.

---

### CTL.STEPFUNCTIONS.ROLE.PERM.S3.WILDCARD.001

**Step Functions Execution Role Grants s3:* On Wildcard Resource**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1, CC6.3;

Execution role grants `s3:*` on `Resource: "*"`. Includes object reads, writes, deletes, bucket-policy modifications, and replication-config changes. Distributed Map state and direct S3 SDK integrations inherit this scope; one workflow becomes a total-S3 pivot.

**Remediation:** Restrict to specific bucket / object ARNs. Split read vs write actions where possible. Reserve s3:DeleteObject / s3:PutBucketPolicy for explicit workflow steps.

---

### CTL.STEPFUNCTIONS.ROLE.PERM.STS.WILDCARD.001

**Step Functions Execution Role Grants sts:AssumeRole On Wildcard Resource**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1, CC6.3;

Execution role grants `sts:AssumeRole` on `Resource: "*"`. Workflow can assume any role in the account that trusts Step Functions (or, transitively, any role this role can reach). Combined with `iam:PassRole`-style abuse, this is a privilege-escalation primitive: workflow assumes admin role, performs admin actions, returns. Audit only shows the workflow's role, not the assumed one — escalation is also detection-evasive.

**Remediation:** Pin Resource to specific role ARNs the workflow actually needs to assume. Audit every assume target's trust policy for confused-deputy protection.

---

### CTL.STEPFUNCTIONS.ROLE.SHARED.001

**Step Functions Execution Role Shared Across Multiple State Machines**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6; soc2: CC6.1, CC6.3;

A single execution role is referenced by more than one state machine. Compromise of any workflow's input / definition gives the attacker the role's full permission set, which now spans all sharing workflows. Each state machine should have its own role scoped to that workflow's specific downstream resources.

**Remediation:** Create per-machine roles. Use IaC modules to keep the boilerplate manageable.

---

### CTL.STEPFUNCTIONS.ROLE.STALE.PERMS.001

**Step Functions Execution Role Has Stale Permissions For Unused Services**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.5.18; nist_800_53_r5: AC-6, CA-7; soc2: CC6.1, CC8.1;

Execution role grants permissions for AWS services the workflow no longer uses (e.g., policy includes `lambda:InvokeFunction` after the workflow migrated to `arn:aws:states:::aws-sdk:` direct integrations and removed the Lambda task). Stale permissions drift in only one direction (additive); each is reviewable but rarely reviewed.

**Remediation:** Run IAM Access Analyzer's unused-access findings; remove permissions whose last-used timestamp is older than the workflow's last definition change. Review quarterly.

---

### CTL.STEPFUNCTIONS.ROLE.TRUST.MULTIPLE.SERVICES.001

**Step Functions Execution Role Trust Includes Unrelated AWS Services**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1, CC6.3;

Step Functions execution role's trust policy permits both `states.amazonaws.com` and other AWS service principals (e.g., `lambda.amazonaws.com`, `events.amazonaws.com`). Sharing an execution role across services amplifies blast radius — compromise of any of the trusted services' invocation paths reaches this role's permissions. Each service should have its own scoped role.

**Remediation:** Split into per-service roles. Each role's trust policy should reference a single AWS service principal.

---

### CTL.STEPFUNCTIONS.ROLE.TRUST.NOSRCACCT.001

**Step Functions Execution Role Trust Policy Lacks SourceAccount/SourceArn**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.16, A.8.20; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2.4; soc2: CC6.1, CC6.6;

Step Functions execution role's trust policy trusts `states.amazonaws.com` but lacks `aws:SourceAccount` and `aws:SourceArn` conditions. Without them, Step Functions in any account can be tricked into assuming this role via a confused-deputy chain (e.g. a Step Functions service in account B calling StartExecution on a state machine pointing at this role's ARN). The two conditions bind the trust to a specific calling account / state machine.

**Remediation:** Add condition keys to the trust policy:
  "Condition": {
    "StringEquals": {"aws:SourceAccount": "111122223333"},
    "ArnLike": {"aws:SourceArn": "arn:aws:states:us-east-1:111122223333:stateMachine:*"}
  }

---

### CTL.STEPFUNCTIONS.SAGEMAKER.NORUNTIME.001

**Step Functions SageMaker Job Without MaxRuntimeInSeconds**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-7; iso_27001_2022: A.8.6; nist_800_53_r5: CM-7; soc2: CC8.1, A1.1;

Step Functions Task using SageMaker Training / Processing job has no `MaxRuntimeInSeconds` configured. Diverging models, runaway data shuffling, or stuck workers consume training capacity until SageMaker's hard limits (1 day default) — full instance-hour bill for zero output.

**Remediation:** Pass MaxRuntimeInSeconds in the Parameters. Tune based on observed training duration + 50% margin.

---

### CTL.STEPFUNCTIONS.SECRETS.001

**Step Functions State Machines Must Not Contain Secrets in Definitions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5(7); soc2: CC6.1;

Step Functions state machine definitions must not contain hardcoded secrets. Definition JSON is visible in the console, API responses, and CloudTrail logs.

**Remediation:** Replace hardcoded secrets with Secrets Manager or Parameter Store references.

---

### CTL.STEPFUNCTIONS.SYNC.NOCATCH.001

**Step Functions .sync Integration Lacks Catch Clause**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4, A1.2;

Step Functions Task using `.sync` integration has no `Catch`. When the downstream resource fails post-submission (job times out, container OOMs, model training diverges), the workflow has no defined cleanup path. Resources may remain in a partial / running state — Glue jobs that still hold concurrency, EMR clusters that still bill, SageMaker endpoints that still serve.

**Remediation:** Add Catch routing to a cleanup state that explicitly stops / cancels / terminates the downstream resource. Standard pattern for Glue: glue:StopJobRun via Lambda task.

---

### CTL.STEPFUNCTIONS.SYNC.NOCLEANUP.001

**Step Functions .sync Catch Path Doesn't Stop Underlying Resource**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-7; iso_27001_2022: A.8.16; nist_800_53_r5: CM-7, SI-11; soc2: CC7.4, A1.1;

Step Functions `.sync` Task has Catch but the Catch routes only to a logging / Fail state — doesn't actually stop the running Glue job, EMR cluster, Batch job, or SageMaker job. Resources continue running / billing after workflow termination. Cost runaway for high-cost integrations (SageMaker training, EMR clusters).

**Remediation:** Add a state in the Catch path that calls the resource's stop API. Glue: glue:StopJobRun. EMR: emr:TerminateJobFlows. Batch: batch:CancelJob. SageMaker: sagemaker:StopTrainingJob.

---

### CTL.STEPFUNCTIONS.SYNC.NORETRY.001

**Step Functions .sync Integration Lacks Retry Clause**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4, A1.2;

Step Functions Task using `.sync` integration (Glue, EMR, Batch, SageMaker, ECS) has no `Retry` clause. `.sync` waits for the downstream resource to terminate; transient failures (control-plane API errors, pre-warmed instance unavailability, capacity errors during job submit) abort the workflow immediately. Standard practice is Retry on the control-plane error class; the resource itself doesn't need to be retried, only the submission.

**Remediation:** Add Retry on control-plane error class:
  "Retry": [{
    "ErrorEquals": ["States.TaskFailed",
      "Glue.AWSGlueException"],
    "IntervalSeconds": 2,
    "MaxAttempts": 3,
    "BackoffRate": 2.0
  }]

---

### CTL.STEPFUNCTIONS.SYNC.SILENT.FALLBACK.001

**Step Functions .sync Resource Doesn't Support Sync Semantics**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.8.32; nist_800_53_r5: CM-3; soc2: CC8.1;

Step Functions Task uses `.sync` integration pattern on a resource type that doesn't natively support synchronous semantics. Step Functions silently falls back to the request-response pattern; the workflow proceeds before the downstream completes. Operators expect "wait for done" behavior and get fire-and-forget instead.

**Remediation:** Replace .sync with `.waitForTaskToken` and a worker that posts SendTaskSuccess on completion. Or use a polling pattern with Wait + Choice.

---

### CTL.STEPFUNCTIONS.SYNC.UNENCRYPTED.CALLBACK.001

**Step Functions .sync Callback Channel SNS / SQS Without SSE-KMS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-28; iso_27001_2022: A.8.24; nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1, 4.2.1; soc2: CC6.7;

Step Functions Task using `.sync` integration receives the downstream's terminal-state notification via SNS or SQS that doesn't have SSE-KMS enabled. Callback payloads carry the Task token plus the downstream result; cleartext SNS / SQS exposes them to anyone with read access on the channel.

**Remediation:** Enable SSE-KMS on the SNS topic / SQS queue used for callback. Use a customer-managed CMK aligned with the workflow's definition key.

---

### CTL.STEPFUNCTIONS.SYNCEXP.APIGW.TIMEOUT.001

**Step Functions Synchronous Express Behind API Gateway With Timeout Race**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4, A1.1;

Synchronous Express workflow invoked from API Gateway has the workflow's max-duration >= API Gateway's integration timeout (default 29s, max 30s). When the workflow approaches the timeout, API Gateway returns 504 to the caller while the workflow keeps running — the caller retries thinking it failed; duplicate workflow invocations result.

**Remediation:** Set workflow TimeoutSeconds <= 25 (5s margin under API GW's 30s ceiling). For workflows that need > 30s, use async Express + DynamoDB-backed status polling.

---

### CTL.STEPFUNCTIONS.TAGS.VERSION.DRIFT.001

**Step Functions Tags Drift Between State Machine Versions**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-8; iso_27001_2022: A.5.9; nist_800_53_r5: CM-8; soc2: CC8.1;

Step Functions state machine and its versions don't share a consistent set of tags (`team`, `cost-center`, `compliance`). Cost allocation reports differ across versions; ABAC / governance scoping breaks on the version that drifted.

**Remediation:** Apply tags at create-version time via IaC. Reconcile via tag-policy with organizations:CreateTags. Backfill via bulk tag-update script.

---

### CTL.STEPFUNCTIONS.TOKEN.PLAINTEXT.001

**Step Functions Task Token Logged Or Persisted In Plaintext**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-28; iso_27001_2022: A.5.16, A.8.24; nist_800_53_r5: IA-5, SC-28; pci_dss_v4.0: 3.5.1, 8.3.2; soc2: CC6.1, CC6.7;

Step Functions Task token (used by `.waitForTaskToken` integrations) is captured in workflow logs (CloudWatch), persisted in SQS / SNS / S3 without encryption, or otherwise reachable in plaintext. Anyone reading the captured token can call `SendTaskSuccess` / `SendTaskFailure` for the workflow, spoofing worker responses and progressing the workflow with attacker-supplied data.

**Remediation:** Mask token in log output (workflow logging.IncludeExecutionData filter or Pass-state redaction). Worker queue (SQS / SNS) carrying the token must use SSE-KMS. Treat the token as a credential.

---

### CTL.STEPFUNCTIONS.VERSION.ACCUMULATION.001

**Step Functions Old Versions Accumulate Without Cleanup**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-8; iso_27001_2022: A.5.9; nist_800_53_r5: CM-8; soc2: CC8.1;

Step Functions state machine has many retained versions (>20) without cleanup. Storage cost is minor but inventory cost is real: list-versions API calls slow, CloudFormation drift detection paginates through them, audit reviews can't quickly identify "what was running last quarter."

**Remediation:** Set up a cleanup pipeline: keep last 5 versions + named-tagged version per quarter for audit. Automate via Lambda triggered weekly.

---

### CTL.STEPFUNCTIONS.VERSION.OFF.001

**Step Functions State Machine Versioning Disabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; iso_27001_2022: A.8.32; nist_800_53_r5: CM-3, CM-2; soc2: CC8.1, A1.2;

Step Functions state machine has versioning disabled (PublishToVersion: false). Each deploy mutates the state machine in place; in-flight executions continue on the new definition mid-run. No rollback target exists; no canary; no immutable record of what was actually deployed at a given time.

**Remediation:** Enable PublishToVersion. Use aliases to route executions; rollback by repointing the alias.

---

### CTL.STEPFUNCTIONS.WAITFORCALLBACK.NOTIMEOUT.001

**Step Functions waitForCallback Without Callback Timeout**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4, A1.2;

Step Functions Task uses Lambda `.waitForCallback` (or any waitFor pattern) without a callback timeout. If the callback worker fails to call `SendTaskSuccess` / `SendTaskFailure` (worker crashed, queue lost the message, permission revoked), the workflow waits forever. Combined with no overall TimeoutSeconds, this is a permanent stall.

**Remediation:** Add TimeoutSeconds matching expected worker turnaround + margin. Add Catch on States.Timeout to clean up.

---

### CTL.STEPFUNCTIONS.WAITFORTOKEN.HEARTBEAT.GT.TIMEOUT.001

**Step Functions HeartbeatSeconds Greater Than TimeoutSeconds (Heartbeat Never Enforced)**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4;

Step Functions Task has `HeartbeatSeconds` >= `TimeoutSeconds`. The Task hits its overall timeout before any heartbeat would have been expected — heartbeat is effectively disabled. Worker hangs are caught only by the longer overall timeout, defeating the point of fast-fail liveness checking.

**Remediation:** Set HeartbeatSeconds < TimeoutSeconds (typical: HeartbeatSeconds 60-120 for multi-hour TimeoutSeconds tasks).

---

### CTL.STEPFUNCTIONS.WAITFORTOKEN.NOHEARTBEAT.001

**Step Functions .waitForTaskToken Without HeartbeatSeconds**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** lifecycle
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: CC7.4, A1.2;

Step Functions Task using `.waitForTaskToken` integration has no `HeartbeatSeconds` configured. Worker can hang indefinitely; Step Functions waits forever (or until the workflow's overall TimeoutSeconds, if set). Heartbeat-based liveness check is the standard pattern; workers send `SendTaskHeartbeat` every N seconds.

**Remediation:** Add HeartbeatSeconds matching the worker's expected heartbeat interval + margin (e.g., worker heartbeats every 30s, HeartbeatSeconds: 60). Worker must call SendTaskHeartbeat within the interval.

---

### CTL.STEPFUNCTIONS.WAITFORTOKEN.NOVALIDATE.001

**Step Functions waitForTaskToken Worker Doesn't Validate Token Identity**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.16, A.8.20; nist_800_53_r5: AC-3, IA-2; pci_dss_v4.0: 8.3.1; soc2: CC6.1, CC6.6;

Step Functions worker receiving a Task token via `.waitForTaskToken` doesn't validate the token's expected characteristics (state machine ARN, expected execution context). Any caller with a stolen / forwarded token can call `SendTaskSuccess` / `SendTaskFailure` for the workflow with attacker-controlled output. Validation is workload-specific but at minimum the worker should match the token's source against a known state-machine ARN.

**Remediation:** Worker SHOULD validate the token's source via DescribeExecution → check that the state-machine ARN matches the expected one. Workers SHOULD also bound the SendTaskSuccess result they accept against a schema appropriate for the calling workflow.

---

### CTL.STEPFUNCTIONS.WORKFLOW.TYPE.MISMATCH.001

**Step Functions Workflow Type Mismatched For Workload Pattern**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-7; iso_27001_2022: A.8.6; nist_800_53_r5: CM-7; soc2: CC8.1, A1.1;

Step Functions Standard workflow used for short, high-volume executions (cost prohibitive: $0.025 per state transition); or Express workflow used for executions that exceed 5 minutes (silent failure at the cap). Workflow type should match workload's runtime profile.

**Remediation:** Standard for: long-running, low-volume, state-transition-bounded. Express for: short, high-volume, IAM-rate-bounded. Convert via blue-green; pricing change is significant.

---

### CTL.STEPFUNCTIONS.XRAY.OFF.001

**Step Functions X-Ray Tracing Disabled On Production Workflow**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-12; iso_27001_2022: A.8.16; nist_800_53_r5: AU-12, SI-4; soc2: CC7.2;

Step Functions production workflow has X-Ray tracing disabled. Cross-service correlation (Lambda + DDB + SQS / SNS spans linked to the workflow execution) is impossible without it; latency / error breakdown per-service and per-state is also lost. Performance investigations rely on per- service log correlation by execution ID, which is fragile.

**Remediation:** Set tracingConfiguration.enabled: true. Configure 100% sampling for low-volume workflows, 10% for high-volume. Add annotations (execution ID, tenant) for queryable traces.

---

