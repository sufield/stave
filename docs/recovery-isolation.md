# Recovery Isolation

Recovery isolation answers: "If your main account is compromised,
can you still recover your data?"

Backups exist. They are encrypted. They are replicated. But if the
KMS key that decrypts them is in the same account as the source
data, a single account compromise destroys both the live data and
the ability to recover it. This is the ransomware path — the
structural Single Point of Failure (SPoF) in disaster recovery.

## The ransomware model

```
Account Compromise → Delete Live Data → Schedule KMS Key Deletion → Unrecoverable Backups
```

The attacker deletes the data, then schedules the encryption key
for deletion. The 7-day KMS deletion window is the only grace
period. If the backup vault and key are in the same account, the
attacker controls both.

## How it works

The extractor identifies backup resources and checks whether the
KMS key resides in a different account:

```yaml
properties:
  backup:
    kind: resource
    recovery_isolation:
      kms_same_account_as_source: true
      kms_key_account: "123456789012"
      data_account: "123456789012"
      admin_is_shared: true
```

## Controls

### CTL.BACKUP.RECOVERY.ISOLATION.001 — KMS key in same account

```
Fires when: kms_same_account_as_source == true
Severity: high
```

The encryption key and the data are in the same account. A single
account compromise can destroy both.

**Remediation:** Create a dedicated recovery account. Generate a KMS
key in the recovery account. Use `aws backup start-copy-job` to
replicate backups there.

### CTL.BACKUP.RECOVERY.ISOLATION.002 — Shared admin (ransomware path)

```
Fires when: admin_is_shared == true
Severity: critical
```

The same principal can delete the source data AND schedule the
KMS key for deletion. This is the ransomware path — a single
compromised credential enables irreversible data destruction.

**Remediation:** Separate data administration from key management.
Use a dedicated backup admin role in the recovery account. Apply
SCPs that deny `kms:ScheduleKeyDeletion` from data admin roles.

## Safety chain: recovery_integrity_failure

```yaml
id: recovery_integrity_failure
controls:
  - CTL.BACKUP.RECOVERY.ISOLATION.001
  - CTL.BACKUP.RECOVERY.ISOLATION.002
  - CTL.BACKUP.EXISTS.001
  - CTL.BACKUP.ENCRYPT.001
escalation_threshold: 2
compound_severity: high
```

A backup exists and is encrypted — but recovery is structurally
tied to the same fate as the source data.

## Key files

| File | Purpose |
|---|---|
| `controls/backup/recovery/CTL.BACKUP.RECOVERY.ISOLATION.001-002.yaml` | 2 isolation controls |
| `chains/recovery_integrity_failure.yaml` | Compound chain definition |
