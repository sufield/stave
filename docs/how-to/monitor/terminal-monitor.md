# How to Run the Terminal Posture Monitor

Display real-time posture status in a terminal pane.

---

## Start the Monitor

```bash
stave monitor --history ./history
```

The monitor shows posture score, severity distribution, top findings, and refreshes every 30 seconds.

## With SLA Context

```bash
stave monitor --history ./history --sla-profile-file sla-policy.yaml
```

Adds SLA burn rate gauges per severity.

## Custom Refresh Interval

```bash
stave monitor --history ./history --refresh 60
```

## JSON Snapshot (Single-Shot)

```bash
stave monitor --history ./history --format json
```

Outputs current state as JSON and exits. Useful for scripting:

```bash
stave monitor --history ./history --format json | \
  jq -e '.sla_burn_rates.critical > 0.8' && \
  notify "Critical SLA burn rate exceeded 80%"
```

## Plain Text for Logging

```bash
stave monitor --history ./history --format plain >> monitor.log
```

## Keyboard Controls

| Key | Action |
|-----|--------|
| `q` | Exit |
| `r` | Immediate refresh |
